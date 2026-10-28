import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Guards the language packs. A missing key or a module file that exists in one
/// language only would silently fall back to English (or surface the raw key),
/// so both are treated as build failures.
void main() {
  final root = Directory('assets/i18n');
  final langs = root
      .listSync()
      .whereType<Directory>()
      .map((d) => d.path.split(Platform.pathSeparator).last)
      .toList()
    ..sort();

  Map<String, String> keysOf(String lang) {
    final dir = Directory('assets/i18n/$lang');
    final table = <String, String>{};
    for (final file in dir.listSync().whereType<File>()) {
      if (!file.path.endsWith('.json')) continue;
      final decoded =
          (jsonDecode(file.readAsStringSync()) as Map).cast<String, dynamic>();
      decoded.forEach((key, value) {
        expect(table.containsKey(key), isFalse,
            reason: 'duplicate key "$key" in $lang');
        table[key] = '$value';
      });
    }
    return table;
  }

  test('at least Arabic and English packs exist', () {
    expect(langs, containsAll(['ar', 'en']));
  });

  test('every language has the same module files', () {
    final modules = {
      for (final lang in langs)
        lang: Directory('assets/i18n/$lang')
            .listSync()
            .whereType<File>()
            .map((f) => f.path.split(Platform.pathSeparator).last)
            .where((n) => n.endsWith('.json'))
            .toSet(),
    };
    final reference = modules[langs.first]!;
    for (final lang in langs.skip(1)) {
      expect(modules[lang], equals(reference),
          reason: '$lang module files differ from ${langs.first}');
    }
  });

  test('every language defines exactly the same keys', () {
    final reference = keysOf(langs.first);
    for (final lang in langs.skip(1)) {
      final other = keysOf(lang);
      final missing = reference.keys.where((k) => !other.containsKey(k)).toList();
      final extra = other.keys.where((k) => !reference.containsKey(k)).toList();
      expect(missing, isEmpty, reason: '$lang is missing keys: $missing');
      expect(extra, isEmpty, reason: '$lang has unknown keys: $extra');
    }
  });

  test('no empty translations', () {
    for (final lang in langs) {
      keysOf(lang).forEach((key, value) {
        expect(value.trim(), isNotEmpty, reason: '$lang/$key is empty');
      });
    }
  });

  test('placeholders match between languages', () {
    final reference = keysOf(langs.first);
    for (final lang in langs.skip(1)) {
      keysOf(lang).forEach((key, value) {
        final expected = _placeholders(reference[key] ?? '');
        final actual = _placeholders(value);
        expect(actual, equals(expected),
            reason: '$lang/$key placeholders differ: $actual vs $expected');
      });
    }
  });
}

Set<String> _placeholders(String value) =>
    RegExp(r'\{(\w+)\}').allMatches(value).map((m) => m.group(1)!).toSet();
