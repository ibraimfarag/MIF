// The QA report is a committed artifact, so it can go stale the moment a method,
// a screen, a control, a language, a binary or a test file changes. This file is
// the gate: it rebuilds the report in memory and refuses a committed copy that
// does not match, the same ratchet `qa/ui/ledger.json` applies to controls.
//
// Regenerating is deliberate, and the diff is the thing to read:
//
//   $env:QA_REPORT_WRITE = "1"; dart run qa\report.dart
//
// It also holds the two claims the report makes about itself: the surface is not
// degenerate, and the report names no machine.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import '../qa/report.dart';

void main() {
  final report = buildReport();

  test('the committed report matches the registries it describes', () {
    for (final pair in [
      [markdownPath, report.markdown],
      [htmlPath, report.html],
    ]) {
      final file = File(pair[0]);
      expect(file.existsSync(), isTrue,
          reason: '${pair[0]} is missing; regenerate with QA_REPORT_WRITE=1');
      expect(normaliseEol(file.readAsStringSync()), normaliseEol(pair[1]),
          reason: '${pair[0]} is stale: the surface changed and the report did '
              'not. Run '
              r'`$env:QA_REPORT_WRITE = "1"; dart run qa\report.dart` and read '
              'the diff.');
    }
  });

  test('no surface is degenerate', () {
    // A parse that silently stopped matching would produce a small, tidy, wrong
    // report; these floors are what make that a failure instead.
    expect(report.methodCount, greaterThan(50),
        reason: 'only ${report.methodCount} methods were read');
    expect(report.dispatchedCount, report.methodCount,
        reason: 'the dispatcher and the registry must agree on the surface');
    expect(report.controlsCount, greaterThan(50),
        reason: 'only ${report.controlsCount} controls were read');
    expect(report.screensCount, greaterThanOrEqualTo(10));
    expect(report.languages.length, greaterThanOrEqualTo(2));
    expect(report.dartTestFiles, greaterThanOrEqualTo(15));
    expect(report.engineTestFiles, greaterThanOrEqualTo(5));
    expect(report.shippedFiles, greaterThanOrEqualTo(5));
    expect(report.pipelineStepCount, greaterThanOrEqualTo(8));
    for (final id in const [
      'flutter.test',
      'engine.test',
      'engine.contract',
      'opsec.verify',
    ]) {
      expect(report.pipelineStepIds, contains(id),
          reason: 'scripts/pipeline.ps1 no longer declares the $id step');
    }
  });

  test('every language on disk is bundled', () {
    expect(report.bundledLanguages, equals(report.languages.keys.toSet()),
        reason: 'a directory under assets/i18n that pubspec.yaml does not list '
            'under `assets:` is not shipped with the app');
  });

  test('every gap has a written reason', () {
    // The same floor the opsec baseline uses: a reason exists to be read, so
    // "n/a" is not one. None of these rows runs here by design, and the reason
    // is what makes that a decision instead of a gap.
    for (final row in report.notRun) {
      expect(row.why.trim().length, greaterThanOrEqualTo(20),
          reason: '${row.method}: the recorded reason is too short to say why '
              'this method is not exercised here');
    }
  });

  test('the report names no machine', () {
    // It is committed, so it must not carry this machine's account or paths: the
    // same rule ط1 applied to the shipped bytes, applied to the report.
    final user = Platform.environment['USERNAME'] ?? '';
    final profile = Platform.environment['USERPROFILE'] ?? '';
    for (final text in [report.markdown, report.html]) {
      expect(text.contains(r'C:\'), isFalse,
          reason: 'a Windows path leaked into the report');
      expect(text.contains(r'\\'), isFalse,
          reason: 'a UNC path leaked into the report');
      for (final secret in [user, profile]) {
        if (secret.length < 4) continue;
        expect(text.toLowerCase().contains(secret.toLowerCase()), isFalse,
            reason: 'the report names a machine-specific value');
      }
      expect(RegExp(r'[^\x00-\x7F]').hasMatch(text), isFalse,
          reason: 'the report must stay ASCII so it renders anywhere');
    }
  });
}
