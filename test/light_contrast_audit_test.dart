import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/theme/contrast.dart';
import 'package:mics_app/features/vulns/screens/vuln_scanner_screen.dart';
import 'package:mics_app/models/audit_models.dart';

/// The light-mode contrast audit (steps أ2 and أ3).
///
/// It measures every colour pair the shipped light UI paints — palette tokens,
/// borders, the accent-button foregrounds, the tinted banners — against WCAG
/// 2.2 (4.5:1 body text, 3:1 large text in §1.4.3, 3:1 UI boundaries and
/// graphics in §1.4.11) and prints the table. Step أ2 took the "before"
/// measurement; step أ3 fixed the palette and turned every ratio into an
/// assertion, so the numbers in `docs/CONTRAST.md` are a floor now instead of a
/// report.
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

  final pairs = <_Pair>[];

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
    ..add(_Pair('error snackbar text', 'SnackBar text on AppColors.red',
        snackText, AppColors.red, _bodyText))
    ..add(_Pair(
        'success snackbar text',
        'SnackBar text on the theme bar (inverseSurface) / intel_screen.dart',
        snackText,
        scheme.inverseSurface,
        _bodyText))
    ..add(_Pair(
        'settings error snackbar text',
        'SnackBar text on AppColors.red at 85 % / settings_screen.dart',
        snackText,
        blendOver(AppColors.red, 0.85, onPage),
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
    expect(AppColors.border, const Color(0xFF74849B));
    expect(AppColors.cyan, const Color(0xFF0E7490));
    expect(AppColors.green, const Color(0xFF065F46));
    expect(AppColors.red, const Color(0xFFBE123C));
    expect(AppColors.orange, const Color(0xFFB23A0B));
    expect(AppColors.yellow, const Color(0xFFB45309));
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
      'yellow': AppColors.yellow,
      'text': AppColors.text,
      'muted': AppColors.muted,
    };
    for (final entry in tokens.entries) {
      expect(measured, contains(entry.value),
          reason: 'AppColors.${entry.key} appears in no audited pair — add '
              'the pair the UI paints before changing the token');
    }
  });

  test('status and severity colours come from the palette, not from literals',
      () {
    // A literal is the dark-mode value: that is what made "Secure" green 1.78:1
    // in light mode. Reading these getters under the light palette is what
    // proves the screens cannot paint a colour this audit never measured.
    expect(_finding(status: 'Secure').statusColor, AppColors.green);
    expect(_finding(status: 'Warning').statusColor, AppColors.orange);
    expect(_finding(status: 'Vulnerable').statusColor, AppColors.red);
    expect(_finding(status: 'Unknown').statusColor, AppColors.muted);
    expect(_finding(severity: 'Critical').severityColor, AppColors.red);
    expect(_finding(severity: 'High').severityColor, AppColors.orange);
    expect(_finding(severity: 'Medium').severityColor, AppColors.yellow);
    expect(_finding(severity: 'Low').severityColor, AppColors.muted);
    expect(cvssColor(9.5), AppColors.red);
    expect(cvssColor(7.5), AppColors.orange);
    expect(cvssColor(5.0), AppColors.yellow);
    expect(cvssColor(2.0), AppColors.muted);
  });

  testWidgets('the success snackbar row measures what Material really paints',
      (tester) async {
    // The row that used to be white-on-white is not taken from a reading of the
    // framework: render the real widget and read the colour back.
    final painted =
        await _paintSnack(tester, const SnackBar(content: Text('msg')));
    final row = pairs.firstWhere((p) => p.what == 'success snackbar text');
    expect(row.bg, scheme.inverseSurface);
    expect(row.fg, painted,
        reason: 'the table must measure the colour the SnackBar actually '
            'paints; if Material changed its default, re-measure the row');
  });

  testWidgets('the error snackbar row measures what Material really paints',
      (tester) async {
    final painted = await _paintSnack(
        tester,
        SnackBar(
          content: const Text('msg'),
          backgroundColor: AppColors.red,
        ));
    final row = pairs.firstWhere((p) => p.what == 'error snackbar text');
    expect(row.bg, AppColors.red);
    expect(row.fg, painted, reason: 're-measure the row if this drifts');
  });

  test('every measured pair clears its WCAG bar, and the table proves it', () {
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
    final below = <String>[];
    for (final p in pairs) {
      final ratio = contrastRatio(p.fg, p.bg);
      final ok = ratio >= p.bar;
      if (!ok) {
        below.add('${ratio.toStringAsFixed(2)}:1 < ${p.bar} — ${p.what} '
            '(${_hex(p.fg)} on ${_hex(p.bg)}) [${p.src}]');
      }
      report.writeln('  ${ratio.toStringAsFixed(2).padLeft(6)}:1  '
          '${ok ? 'PASS' : 'FAIL'}  >= ${p.bar}  '
          '${p.what.padRight(36)} ${_hex(p.fg)} on ${_hex(p.bg)}  [${p.src}]');
    }
    report.writeln('  => ${pairs.length - below.length} of ${pairs.length} '
        'pairs clear their bar');
    stdout.writeln(report);
    expect(below, isEmpty,
        reason: 'these pairs are below their WCAG bar:\n${below.join('\n')}');
  });
}

/// Renders a real `SnackBar` over the light theme and returns the colour its
/// text was actually painted in.
Future<Color?> _paintSnack(WidgetTester tester, SnackBar bar) async {
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
  ScaffoldMessenger.of(context).showSnackBar(bar);
  await tester.pump();
  await tester.pump(const Duration(seconds: 1));
  return tester.renderObject<RenderParagraph>(find.text('msg')).text.style?.color;
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