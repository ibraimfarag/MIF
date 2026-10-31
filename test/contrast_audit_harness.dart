import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/theme/contrast.dart';
import 'package:mics_app/features/vulns/screens/vuln_scanner_screen.dart';
import 'package:mics_app/models/audit_models.dart';

/// The machinery both contrast audits share, so the light and the dark audit
/// cannot drift apart in what they measure or in how they report it.
///
/// `test/light_contrast_audit_test.dart` (steps أ2/أ3) and
/// `test/dark_contrast_audit_test.dart` (small step 4 of `docs/TODO.md` §0.5)
/// each pin the palette, declare the pairs the shipped UI paints, and then call
/// the `register…` functions below. Everything here is asserted, and the table
/// is printed as the record that `docs/CONTRAST.md` quotes.
///
/// This file is not a test: `flutter test` only collects `*_test.dart`.

/// One pair the shipped UI actually paints.
class ContrastPair {
  const ContrastPair(this.what, this.src, this.fg, this.bg, this.bar);

  /// What the eye sees, unique per row.
  final String what;

  /// Where the colours come from, so a failure names the file to open.
  final String src;

  final Color fg;
  final Color bg;

  /// The WCAG bar that applies: [bodyTextBar] for text, [boundaryBar] for large
  /// text and UI.
  final double bar;
}

/// WCAG 2.2 §1.4.3 body text.
const double bodyTextBar = 4.5;

/// WCAG 2.2 §1.4.11 boundaries, icons and large text.
const double boundaryBar = 3.0;

/// The `#RRGGBB` form the table and `docs/CONTRAST.md` are written in.
String hexOf(Color color) => '#${color
    .toARGB32()
    .toRadixString(16)
    .padLeft(8, '0')
    .substring(2)
    .toUpperCase()}';

/// An audit finding with only the fields the colour getters read.
AuditFinding findingOf({String status = 'Unknown', String severity = 'Low'}) =>
    AuditFinding(
      section: 'defender',
      item: 'x',
      status: status,
      severity: severity,
      description: '',
      fixAvailable: false,
    );

/// Renders a real `SnackBar` over [theme] and returns the colour its text was
/// actually painted in — the row is read back out of the render tree, not
/// derived from a reading of the framework.
Future<Color?> paintSnackText(
    WidgetTester tester, SnackBar bar, ThemeData theme) async {
  late BuildContext context;
  await tester.pumpWidget(MaterialApp(
    theme: theme,
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
  return tester
      .renderObject<RenderParagraph>(find.text('msg'))
      .text
      .style
      ?.color;
}

/// The contrast formula's own test: the WCAG reference values, and the
/// source-over compositing [blendOver] claims to implement.
void registerFormulaTest() {
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
}

/// The palette under audit is the one that ships: every token is compared with
/// the literal in `app_theme.dart`, so a token cannot change unnoticed.
void registerPaletteIdentityTest({
  required String mode,
  required Map<String, Color> expected,
}) {
  test('the colour under audit is the shipped $mode palette', () {
    for (final entry in expected.entries) {
      expect(_token(entry.key), entry.value,
          reason: 'AppColors.${entry.key} must stay the shipped $mode token — '
              're-measure before changing it');
    }
  });
}

/// Every palette token has to appear in a pair, otherwise a token can be
/// changed into a colour no audit ever measured.
void registerCoverageTest({
  required List<ContrastPair> pairs,
  required Map<String, Color> tokens,
}) {
  final measured = <Color>{
    for (final pair in pairs) ...<Color>[pair.fg, pair.bg],
  };
  test('every palette token is part of an audited pair', () {
    for (final entry in tokens.entries) {
      expect(measured, contains(entry.value),
          reason: 'AppColors.${entry.key} appears in no audited pair — add '
              'the pair the UI paints before changing the token');
    }
  });
}

/// `AuditFinding.statusColor` / `severityColor` and `cvssColor` must return
/// palette tokens. A literal is the *other* mode's value: that is what made
/// "Secure" green 1.78:1 in light mode.
void registerStatusColourTest() {
  test('status and severity colours come from the palette, not from literals',
      () {
    expect(findingOf(status: 'Secure').statusColor, AppColors.green);
    expect(findingOf(status: 'Warning').statusColor, AppColors.orange);
    expect(findingOf(status: 'Vulnerable').statusColor, AppColors.red);
    expect(findingOf(status: 'Unknown').statusColor, AppColors.muted);
    expect(findingOf(severity: 'Critical').severityColor, AppColors.red);
    expect(findingOf(severity: 'High').severityColor, AppColors.orange);
    expect(findingOf(severity: 'Medium').severityColor, AppColors.yellow);
    expect(findingOf(severity: 'Low').severityColor, AppColors.muted);
    expect(cvssColor(9.5), AppColors.red);
    expect(cvssColor(7.5), AppColors.orange);
    expect(cvssColor(5.0), AppColors.yellow);
    expect(cvssColor(2.0), AppColors.muted);
  });
}

/// The two snackbar rows are not derived from a reading of the framework: the
/// real widget is rendered and the painted colour is read back, then compared
/// with the colour the table measured.
void registerSnackbarRowTests({
  required List<ContrastPair> pairs,
  required ThemeData theme,
}) {
  testWidgets('the success snackbar row measures what Material really paints',
      (tester) async {
    final painted =
        await paintSnackText(tester, const SnackBar(content: Text('msg')), theme);
    final row = pairs.firstWhere((p) => p.what == 'success snackbar text');
    expect(row.bg, theme.colorScheme.inverseSurface);
    expect(row.fg, painted,
        reason: 'the table must measure the colour the SnackBar actually '
            'paints; if Material changed its default, re-measure the row');
  });

  testWidgets('the error snackbar row measures what Material really paints',
      (tester) async {
    final painted = await paintSnackText(
        tester,
        SnackBar(
          content: const Text('msg'),
          backgroundColor: AppColors.red,
        ),
        theme);
    final row = pairs.firstWhere((p) => p.what == 'error snackbar text');
    expect(row.bg, AppColors.red);
    expect(row.fg, painted, reason: 're-measure the row if this drifts');
  });
}

/// Prints the WCAG 2.2 table for [pairs] and fails while any row is below its
/// bar. The printed line is what `docs/CONTRAST.md` records.
void registerWcagTableTest({
  required String subject,
  required List<ContrastPair> pairs,
}) {
  test('every measured pair clears its WCAG bar, and the table proves it', () {
    expect(pairs.map((p) => p.what).toSet(), hasLength(pairs.length),
        reason: 'two rows share a name, so the table is not readable as a '
            'record');
    expect(pairs.map((p) => p.bar).toSet(), <double>{bodyTextBar, boundaryBar},
        reason: 'only the two WCAG bars may appear in the table');

    final report = StringBuffer()
      ..writeln('')
      ..writeln('WCAG 2.2 contrast — $subject, ${pairs.length} pairs')
      ..writeln('  bar 4.5 = body text · bar 3.0 = large text, boundary, '
          'graphic');
    final below = <String>[];
    for (final p in pairs) {
      final ratio = contrastRatio(p.fg, p.bg);
      final ok = ratio >= p.bar;
      if (!ok) {
        below.add('${ratio.toStringAsFixed(2)}:1 < ${p.bar} — ${p.what} '
            '(${hexOf(p.fg)} on ${hexOf(p.bg)}) [${p.src}]');
      }
      report.writeln('  ${ratio.toStringAsFixed(2).padLeft(6)}:1  '
          '${ok ? 'PASS' : 'FAIL'}  >= ${p.bar}  '
          '${p.what.padRight(36)} ${hexOf(p.fg)} on ${hexOf(p.bg)}  [${p.src}]');
    }
    report.writeln('  => ${pairs.length - below.length} of ${pairs.length} '
        'pairs clear their bar');
    stdout.writeln(report);
    expect(below, isEmpty,
        reason: 'these pairs are below their WCAG bar:\n${below.join('\n')}');
  });
}

Color _token(String name) => switch (name) {
      'background' => AppColors.background,
      'surface' => AppColors.surface,
      'border' => AppColors.border,
      'cyan' => AppColors.cyan,
      'green' => AppColors.green,
      'red' => AppColors.red,
      'orange' => AppColors.orange,
      'yellow' => AppColors.yellow,
      'text' => AppColors.text,
      'muted' => AppColors.muted,
      _ => throw ArgumentError.value(name, 'name', 'unknown palette token'),
    };
