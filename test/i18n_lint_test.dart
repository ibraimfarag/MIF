import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Fails when user-visible English/Arabic copy is written directly in a widget
/// instead of going through `context.tr(...)`.
///
/// What is *not* a violation:
///  * pure interpolation such as `Text('$pct%')` or `Text('${a} :: ${b}')`;
///  * brand/legal/path strings listed in [_allowed] (they are intentionally
///    not translated).
///
/// Adding a new allowed literal is a deliberate act: it means "this string must
/// never be translated".
const _allowed = <String>{
  'MI CS',
  'MI CS — Mourad Ibrahim Cyber Security',
  'GPL-3.0-or-later · no telemetry · offline-first',
  r'C:\ProgramData\MICS\settings.json',
};

void main() {
  test('no hardcoded user-facing copy in lib/', () {
    final violations = <String>[];
    final files = Directory('lib')
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith('.dart'));

    final textCall = RegExp(r"(?<!Selectable)Text\(\s*'((?:[^'\\]|\\.)*)'");

    for (final file in files) {
      // 1) blank out interpolations (they may contain their own quotes, e.g.
      //    `padLeft(2, '0')`), 2) blank out the sanctioned `context.tr('key')`
      //    calls. What is left inside `Text('...')` is user-facing copy.
      final source = file
          .readAsStringSync()
          .replaceAll(RegExp(r'\$\{[^{}]*\}'), 'X')
          .replaceAll(RegExp(r"context\.tr\('([^']*)'\)"), 'TR');
      final lines = source.split('\n');
      for (final match in textCall.allMatches(source)) {
        final literal = match.group(1)!;
        if (_allowed.contains(literal)) continue;
        final stripped = literal
            .replaceAll(RegExp(r'\$\{[^}]*\}'), '')
            .replaceAll(RegExp(r'\$\w+'), '');
        // Any word left over after removing interpolations is copy.
        final hasWord = RegExp(r'[A-Za-z]{3,}|[\u0600-\u06FF]{2,}')
            .hasMatch(stripped);
        if (!hasWord) continue;
        final lineNo = '\n'.allMatches(source.substring(0, match.start)).length + 1;
        violations.add('${file.path}:$lineNo  "$literal"  '
            '(line: ${lines[lineNo - 1].trim()})');
      }
    }

    expect(violations, isEmpty,
        reason: 'Move these strings to assets/i18n/<lang>/<module>.json and '
            'use context.tr(...):\n${violations.join('\n')}');
  });
}
