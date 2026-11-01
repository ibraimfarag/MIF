// The control ledger: what each screen exposed the last time a human agreed
// with it.
//
// A sweep that only asserts "no exception" passes just as happily after a
// button is deleted. The ledger is the ratchet the other way round: the sorted
// list of controls is committed, so adding one and removing one both show up in
// review. Regenerating is deliberate, not automatic:
//
//   $env:UI_LEDGER_WRITE = "1"; flutter test --no-pub test/ui_screens_test.dart
//
// and the resulting diff is the thing to read.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

const ledgerPath = 'qa/ui/ledger.json';

const _about = 'Every interactive control each screen (and the shell) exposed '
    'during its sweep, sorted. Written by qa/ui/harness.dart; regenerate with '
    'UI_LEDGER_WRITE=1. A diff here is a change to what a user can press.';

bool get _writingFile => Platform.environment['UI_LEDGER_WRITE'] == '1';

/// Compares [found] with the committed entry for [key], and fails with both
/// directions of the difference when they disagree.
Future<void> expectLedger(String key, List<String> found) async {
  final actual = [...found]..sort();
  final ledger = _read();

  if (_writingFile) {
    ledger[key] = actual;
    _write(ledger);
    return;
  }

  final expected = ledger[key];
  if (expected == null) {
    fail('$key has no ledger entry. Either this is new, or the screen is new - '
        'regenerate with UI_LEDGER_WRITE=1 and review the diff. Would have '
        'added:\n${const JsonEncoder.withIndent('  ').convert(actual)}');
  }
  final added = actual.where((c) => !expected.contains(c)).toList();
  final removed = expected.where((c) => !actual.contains(c)).toList();
  expect(added, isEmpty,
      reason: '$key gained control(s) that are not in the ledger: $added');
  expect(removed, isEmpty,
      reason: '$key lost control(s) the ledger still lists: $removed');
}

Map<String, List<String>> _read() {
  final file = File(ledgerPath);
  if (!file.existsSync()) return {};
  final decoded = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
  final entries = (decoded['entries'] as Map?) ?? const {};
  return entries.map((k, v) => MapEntry('$k', (v as List).cast<String>()));
}

void _write(Map<String, List<String>> entries) {
  final sorted = <String, List<String>>{};
  for (final key in entries.keys.toList()..sort()) {
    sorted[key] = [...entries[key]!]..sort();
  }
  final body = const JsonEncoder.withIndent('  ')
      .convert({'about': _about, 'entries': sorted});
  File(ledgerPath).writeAsStringSync('$body\n');
}