import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/theme/contrast.dart';
import 'package:mics_app/features/vulns/screens/vuln_scanner_screen.dart';
import 'package:mics_app/models/audit_models.dart';

/// The light-mode contrast audit (step أ2).
///
/// It measures every colour pair the shipped light UI paints — palette tokens,
/// borders, the severity colours that ignore the palette, and text on the
/// tinted banners — against WCAG 2.2 (4.5:1 body text, 3:1 large text in
/// §1.4.3, 3:1 UI boundaries and graphics in §1.4.11) and prints the table.
///
/// This step *measures*: the table is the "before" record, and the assertions
/// that pin each ratio arrive with the palette fix (step أ3). What is enforced
/// here is that the measurement cannot silently stop covering something — every
/// palette token, and every colour a status/severity getter can return, has to
/// appear in the table.
///
/// Reproduce the numbers with:
///   flutter test --no-pub test/light_contrast_audit_test.dart
void main() {
  // The palette is static and mutable (app_theme.dart), so the mode under audit
  // is pinned before a single colour is read: this file is about light mode.
  AppColors.applyLight();
  final theme = AppTheme.lightTheme;
  final scheme = theme.colorScheme;
  // No snackBarTheme is configured, so a SnackBar keeps Material's own default
  // text colour (snack_bar.dart: `snackBarTheme.contentTextStyle ??
  // onInverseSurface`); the three screens that snack reuse `AppColors.surface`
  // or `AppColors.red` as the background.
  final snackText =
      theme.snackBarTheme.contentTextStyle?.color ?? scheme.onInverseSurface;

  final onPage = AppColors.background;
  final onCard = AppColors.surface;
  final surfaces = <(String, Color)>[
    ('the page', onPage),
    ('a card', onCard),
  ];

  final pairs = <_Pair>[];

  // Palette tokens as text, on both surfaces the UI paints them on.
  for (final (what, token, color) in <(String, String, Color)>[
    ('body text', 'AppColors.text', AppColors.text),
    ('secondary text', 'AppColors.muted', AppColors.muted),
    ('accent text', 'AppColors.cyan', AppColors.cyan),
    ('success text', 'AppColors.green', AppColors.green),
    ('danger text', 'AppColors.red', AppColors.red),
    ('warning text', 'AppColors.orange', AppColors.orange),
  ]) {
    for (final (label, bg) in surfaces) {
      pairs.add(_Pair('$what on $label', '$token / app_theme.dart', color, bg,
          _bodyText));
    }
  }

  // Boundaries: a card or input edge against what it sits on.
  pairs
    ..add(_Pair('card border on the page', 'AppColors.border / app_theme.dart',
        AppColors.border, onPage, _boundary))
    ..add(_Pair('card border on a card', 'AppColors.border / app_theme.dart',
        AppColors.border, onCard, _boundary));

  // Foreground on an accent fill.
  pairs
    ..add(_Pair(
        'filled-button label',
        'filledButtonTheme.foregroundColor on primary / app_theme.dart',
        AppColors.background,
        AppColors.cyan,
        _bodyText))
    ..add(_Pair('declared onPrimary', 'colorScheme.onPrimary on primary',
        scheme.onPrimary, AppColors.cyan, _bodyText))
    ..add(_Pair('declared onSecondary', 'colorScheme.onSecondary on secondary',
        scheme.onSecondary, AppColors.green, _bodyText))
    ..add(_Pair('declared onError', 'colorScheme.onError on error',
        scheme.onError, AppColors.red, _bodyText))
    ..add(_Pair('error snackbar text', 'SnackBar default text on AppColors.red',
        snackText, AppColors.red, _bodyText))
    ..add(_Pair(
        'success snackbar text',
        'SnackBar default text on AppColors.surface / intel_screen.dart',
        snackText,
        onCard,
        _bodyText));

  // Non-text UI: icons and the rail indicator, which WCAG scores at 3:1.
  pairs
    ..add(_Pair(
        'selected nav-rail icon',
        'cyan on indicatorColor (cyan 15 % over surface) / app_theme.dart',
        AppColors.cyan,
        blendOver(AppColors.cyan, 0.15, onCard),
        _boundary))
    ..add(_Pair('unselected nav-rail icon',
        'navigationRailTheme.unselectedIconTheme', AppColors.muted, onCard,
        _boundary));

  // Text on the tinted banners, measured as the filled colour they really are.
  pairs
    ..add(_Pair(
        'body text on the success banner',
        'text on green 5 % / incidents_screen.dart',
        AppColors.text,
        blendOver(AppColors.green, 0.05, onCard),
        _bodyText))
    ..add(_Pair(
        'error-banner text',
        'orange on red 8 % / ids_screen.dart, network_monitor_screen.dart',
        AppColors.orange,
        blendOver(AppColors.red, 0.08, onCard),
        _bodyText))
    ..add(_Pair(
        'block-action badge text',
        'red on red 15 % / network_monitor_screen.dart',
        AppColors.red,
        blendOver(AppColors.red, 0.15, onCard),
        _bodyText))
    ..add(_Pair(
        'allow-action badge text',
        'green on green 15 % / network_monitor_screen.dart',
        AppColors.green,
        blendOver(AppColors.green, 0.15, onCard),
        _bodyText));

  // Severity/status colours that are literals rather than palette tokens, so
  // they keep their dark-theme values in light mode (audit_models.dart has no
  // light variant, and the CVSS yellow is one hex shared by two screens).
  for (final (what, color) in <(String, Color)>[
    ('status/severity green', const Color(0xFF34D399)),
    ('status/severity orange', const Color(0xFFFB923C)),
    ('status/severity red', const Color(0xFFF43F5E)),
    ('status/severity slate', const Color(0xFF64748B)),
    ('CVSS 4.0-6.9 yellow', const Color(0xFFEAB308)),
  ]) {
    for (final (label, bg) in surfaces) {
      pairs.add(_Pair(
          '$what on $label',
          'hardcoded in audit_models.dart / vuln_scanner_screen.dart',
          color,
          bg,
          _bodyText));
    }
  }

  final measured = <Color>{
    for (final p in pairs) ...<Color>[p.fg, p.bg],
  };

  test('the contrast formula reproduces the WCAG reference values', () {
    const black = Color(0xFF000000);
    const white = Color(0xFFFFFFFF);
    expect(contrastRatio(black, white), closeTo(21.0, 0.001));
    expect(contrastRatio(white, black), closeTo(21.0, 0.001));
    expect(contrastRatio(white, white), closeTo(1.0, 0.0001));
    // #767676 on white is the canonical grey that just reaches AA body text.
    expect(contrastRatio(const Color(0xFF767676), white), closeTo(4.54, 0.005));
    // Source-over compositing: 8 % red over white, per channel.
    final tint = blendOver(const Color(0xFFE11D48), 0.08, white);
    expect(tint.a, 1.0);
    expect((tint.r * 255).round(), 253);
    expect((tint.g * 255).round(), 237);
    expect((tint.b * 255).round(), 240);
  });

  test('the colour under audit is the shipped light palette', () {
    expect(AppColors.background, const Color(0xFFF4F7FB));
    expect(AppColors.surface, const Color(0xFFFFFFFF));
    expect(AppColors.border, const Color(0xFFDDE4EE));
    expect(AppColors.cyan, const Color(0xFF0891B2));
    expect(AppColors.green, const Color(0xFF059669));
    expect(AppColors.red, const Color(0xFFE11D48));
    expect(AppColors.orange, const Color(0xFFEA580C));
    expect(AppColors.text, const Color(0xFF0F172A));
    expect(AppColors.muted, const Color(0xFF5B6B7F));
  });

  test('every palette token is part of an audited pair', () {
    final tokens = <String, Color>{
      'background': AppColors.background,
      'surface': AppColors.surface,
      'border': AppColors.border,
      'cyan': AppColors.cyan,
      'green': AppColors.green,
      'red': AppColors.red,
      'orange': AppColors.orange,
      'text': AppColors.text,
      'muted': AppColors.muted,
    };
    for (final entry in tokens.entries) {
      expect(measured, contains(entry.value),
          reason: 'AppColors.${entry.key} appears in no audited pair — add '
              'the pair the UI paints before changing the token');
    }
  });

  test('every status/severity colour the UI can paint is in the table', () {
    final painted = <String, Color>{
      for (final s in ['Secure', 'Warning', 'Vulnerable', 'Unknown'])
        'AuditFinding(status: $s).statusColor': _finding(status: s).statusColor,
      for (final s in ['Critical', 'High', 'Medium', 'Low'])
        'AuditFinding(severity: $s).severityColor':
            _finding(severity: s).severityColor,
      'cvssColor(9.5)': cvssColor(9.5),
      'cvssColor(7.5)': cvssColor(7.5),
      'cvssColor(5.0)': cvssColor(5.0),
      'cvssColor(2.0)': cvssColor(2.0),
    };
    for (final entry in painted.entries) {
      expect(measured, contains(entry.value),
          reason: '${entry.key} paints ${_hex(entry.value)}, which no audited '
              'pair measures');
    }
  });

  testWidgets('the snackbar row measures what the widget really paints',
      (tester) async {
    // The worst pair in the table is a SnackBar whose background one screen
    // overrides: the text colour is Material's default, not something this repo
    // sets. So render the real thing and read the colour back, instead of
    // trusting a reading of the framework source.
    late BuildContext context;
    await tester.pumpWidget(MaterialApp(
      theme: AppTheme.lightTheme,
      home: Scaffold(
        body: Builder(builder: (inner) {
          context = inner;
          return const SizedBox();
        }),
      ),
    ));
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: const Text('synced'),
      backgroundColor: AppColors.surface,
    ));
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));

    final rendered =
        tester.renderObject<RenderParagraph>(find.text('synced')).text.style;
    final row = pairs.firstWhere((p) => p.what == 'success snackbar text');
    expect(row.bg, AppColors.surface);
    expect(row.fg, rendered?.color,
        reason: 'the table must measure the colour the SnackBar actually '
            'paints; if Material changed its default, re-measure the row');
  });

  test('the shipped light palette, measured against WCAG 2.2', () {
    expect(pairs.map((p) => p.what).toSet(), hasLength(pairs.length),
        reason: 'two rows share a name, so the table is not readable as a '
            'record');
    expect(pairs.map((p) => p.bar).toSet(), <double>{_bodyText, _boundary},
        reason: 'only the two WCAG bars may appear in the table');

    final report = StringBuffer()
      ..writeln('')
      ..writeln('WCAG 2.2 contrast — MI CS light palette, ${pairs.length} pairs')
      ..writeln('  bar 4.5 = body text · bar 3.0 = large text, boundary, '
          'graphic');
    var below = 0;
    for (final p in pairs) {
      final ratio = contrastRatio(p.fg, p.bg);
      final ok = ratio >= p.bar;
      if (!ok) below++;
      report.writeln('  ${ratio.toStringAsFixed(2).padLeft(6)}:1  '
          '${ok ? 'PASS' : 'FAIL'}  >= ${p.bar}  '
          '${p.what.padRight(36)} ${_hex(p.fg)} on ${_hex(p.bg)}  [${p.src}]');
    }
    report.writeln('  => $below of ${pairs.length} pairs are below their bar');
    stdout.writeln(report);
  });
}

/// One pair the shipped light UI actually paints.
class _Pair {
  const _Pair(this.what, this.src, this.fg, this.bg, this.bar);

  /// What the eye sees, unique per row.
  final String what;

  /// Where the colours come from, so a failure names the file to open.
  final String src;

  final Color fg;
  final Color bg;

  /// The WCAG bar that applies: 4.5 for text, 3.0 for large text and UI.
  final double bar;
}

const double _bodyText = 4.5;
const double _boundary = 3.0;

AuditFinding _finding({String status = 'Unknown', String severity = 'Low'}) =>
    AuditFinding(
      section: 'defender',
      item: 'x',
      status: status,
      severity: severity,
      description: '',
      fixAvailable: false,
    );

String _hex(Color color) => '#${color
    .toARGB32()
    .toRadixString(16)
    .padLeft(8, '0')
    .substring(2)
    .toUpperCase()}';
