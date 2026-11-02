// The registry is the contract's table of contents, so it gets its own test:
// it must name exactly the methods the engine dispatches, and every row must be
// able to produce at least one case. A method that exists in the engine but not
// here would never be tested, which is the one failure this file exists to make
// impossible.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import '../qa/registry.dart';

const _classes = {'pure', 'read', 'sandbox', 'mutating', 'network', 'desktop'};
const _shapes = {'string', 'object', 'array', 'error', 'any'};

/// `mutating`, `network` and `desktop` rows may only carry refusal cases: the
/// harness runs on the machine that is being protected.
const _neverHappyPath = {'mutating', 'network', 'desktop'};

void main() {
  final registry = readJsonMap(methodsPath);
  final rows = methodRows(methodsPath);
  final dispatched = dispatchedMethods(registry['engine'] as String);

  test('the registry parses and has rows', () {
    expect(rows, isNotEmpty);
    expect(registry['version'], isA<int>(),
        reason: 'keep a version so a reader knows how to read the file');
    expect(File(registry['engine'] as String).existsSync(), isTrue,
        reason: 'the registry names the source it describes; it must exist');
  });

  test('the dispatcher parse is not degenerate', () {
    // If the arm pattern ever stops matching the source (a reformat, a moved
    // match block) the equality test below would pass vacuously against an
    // empty set. This is the guard against that.
    expect(dispatched.length, greaterThan(50),
        reason: 'the dispatcher parse found only ${dispatched.length} methods; '
            'the arm pattern no longer matches the source formatting');
  });

  test('every dispatched method has a row, and no row is unknown', () {
    final registered = rows.map((r) => r['method'] as String).toSet();

    final missing = dispatched.difference(registered).toList()..sort();
    final extra = registered.difference(dispatched).toList()..sort();

    expect(missing, isEmpty,
        reason: 'the engine dispatches these but qa/methods.json does not '
            'describe them: $missing');
    expect(extra, isEmpty,
        reason: 'qa/methods.json describes methods the engine does not '
            'dispatch: $extra');
    expect(dispatched.length, rows.length,
        reason: 'one row per method, no duplicates');
  });

  test('no method is listed twice', () {
    final seen = <String>{};
    for (final row in rows) {
      final method = row['method'] as String;
      expect(seen.add(method), isTrue, reason: '$method is listed twice');
    }
  });

  test('every row says what class it is and why', () {
    for (final row in rows) {
      final method = row['method'] as String;
      expect(_classes, contains(row['class']),
          reason: '$method: class must be one of $_classes');
      final note = row['note'];
      expect(note, isA<String>(),
          reason: '$method: every row carries a note, it is the documentation');
      expect((note as String).trim(), isNotEmpty,
          reason: '$method: the note is empty');
    }
  });

  test('every row can produce at least one case', () {
    for (final row in rows) {
      final method = row['method'] as String;
      final cases = [
        row['expect'] != null,
        row['missing'] == true,
        row['invalid'] != null,
        row['extra'] is List && (row['extra'] as List).isNotEmpty,
      ].where((e) => e).length;
      final skipped = row['skip'] != null;
      expect(cases > 0 || skipped, isTrue,
          reason: '$method has nothing to run and no reason recorded: give it '
              'an expect/missing/invalid/extra case, or a skip reason');
    }
  });

  test('the machine is never mutated by a happy path', () {
    for (final row in rows) {
      final method = row['method'] as String;
      if (_neverHappyPath.contains(row['class'])) {
        expect(row['expect'], isNull,
            reason: '$method is ${row['class']} and must not carry a happy '
                'path; refusal cases only');
      }
      if (row['skip'] != null) {
        expect(row['expect'], isNull,
            reason: '$method is skipped, so an expect would silently not run');
        expect((row['skip'] as String).trim(), isNotEmpty,
            reason: '$method: the skip reason is empty');
      }
    }
  });

  test('shapes and assertions are from the allowed vocabulary', () {
    for (final row in rows) {
      final method = row['method'] as String;
      final expectShape = row['expect'];
      if (expectShape != null) {
        expect(_shapes, contains(expectShape),
            reason: '$method: expect must be one of $_shapes');
      }
      final want = row['want'];
      if (want != null) {
        expect(want, isA<Map>(),
            reason: '$method: want is a flat map of field -> value');
        expect(expectShape, 'object',
            reason: '$method: want only applies to an object result');
      }
      final params = row['params'];
      expect(params == null || params is Map, isTrue,
          reason: '$method: params is a map, or null for no params');
    }
  });

  test('refusal cases carry parameters that fail for a real reason', () {
    for (final row in rows) {
      final method = row['method'] as String;
      for (final key in ['params', 'invalid']) {
        final value = row[key];
        if (value is Map) _assertNoPlaceholderEscapes(method, key, value);
      }
      final extras = row['extra'];
      if (extras is List) {
        for (final extra in extras) {
          final item = (extra as Map).cast<String, dynamic>();
          expect((item['case'] as String?)?.trim(), isNotEmpty,
              reason: '$method: an extra case needs a name');
          expect(_shapes, contains(item['expect']),
              reason: '$method: extra case ${item['case']} has an unknown '
                  'expect');
          _assertNoPlaceholderEscapes(
              method, 'extra/${item['case']}', item['params']);
        }
      }
    }
  });
}

/// Every string in [value] that looks like a path placeholder must be an
/// `@sandbox/...` one: the harness substitutes those and nothing else, so a
/// literal `C:\...` in the registry would make the suite machine-specific.
void _assertNoPlaceholderEscapes(String method, String field, Object? value) {
  if (value is String) {
    if (value.startsWith('@')) {
      expect(value.startsWith('@sandbox/'), isTrue,
          reason: '$method $field: unknown placeholder $value');
    }
    return;
  }
  if (value is Map) {
    for (final entry in value.entries) {
      _assertNoPlaceholderEscapes(method, '$field.${entry.key}', entry.value);
    }
    return;
  }
  if (value is List) {
    for (var i = 0; i < value.length; i++) {
      _assertNoPlaceholderEscapes(method, '$field[$i]', value[i]);
    }
  }
}