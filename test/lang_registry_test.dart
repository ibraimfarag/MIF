// One language = one line in `AppLang.all` plus one folder. Nothing else in the
// app knows a language by name, so these two things have to agree, and a
// language that is bundled but has no pack (or a pack nobody bundled) is a bug
// that only shows up on a user's screen:
//
//   * the picker would list a language that renders every key as `settings.dnd`;
//   * or a translated folder would be shipped and unreachable.
//
// This test is the seam. It also pins the two facts the rest of the UI reads
// instead of comparing against Arabic: each language's code (which is the asset
// folder *and* the value the engine stores) and its direction.

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';

void main() {
  test('every bundled language has a pack folder with the same modules', () {
    // `i18nModules` is the load order, and a module file is optional (the
    // loader tolerates a module nobody has translated yet): what must hold is
    // that every language ships *the same* files, and that no file is a module
    // the loader will never look for.
    final reference = _moduleFiles(AppLang.all.first.code);
    expect(reference, isNotEmpty);
    for (final lang in AppLang.all) {
      final files = _moduleFiles(lang.code);
      expect(files.difference(reference), isEmpty,
          reason: 'assets/i18n/${lang.code} has modules ${AppLang.all.first.code} '
              'does not: ${files.difference(reference)}');
      expect(reference.difference(files), isEmpty,
          reason: 'assets/i18n/${lang.code} is missing '
              '${reference.difference(files)}');
    }
    final known = {for (final m in i18nModules) '$m.json'};
    expect(reference.difference(known), isEmpty,
        reason: 'these files are not in i18nModules, so nothing loads them: '
            '${reference.difference(known)}');
  });

  test('every bundled language is declared as an asset', () {
    // The loader swallows a failed asset read on purpose ("a module that has not
    // been translated yet must not break the app"), so a language folder that
    // pubspec.yaml forgets is not an error anywhere: the whole UI just renders
    // raw keys. This is the only place that can catch it.
    final pubspec = File('pubspec.yaml').readAsStringSync();
    for (final lang in AppLang.all) {
      expect(pubspec.contains('assets/i18n/${lang.code}/'), isTrue,
          reason: 'pubspec.yaml does not declare assets/i18n/${lang.code}/, so '
              '${lang.englishName} would render as raw keys');
    }
  });

  test('no pack is shipped without a bundled language', () {
    final folders = Directory('assets/i18n')
        .listSync()
        .whereType<Directory>()
        .map((d) => d.path.split(Platform.pathSeparator).last)
        .toSet();
    final bundled = {for (final lang in AppLang.all) lang.code};
    expect(folders.difference(bundled), isEmpty,
        reason: 'these packs are shipped but unreachable: '
            '${folders.difference(bundled)} - add them to AppLang.all');
  });

  test('codes are unique, lower-case tags that match their folder', () {
    final seen = <String>{};
    for (final lang in AppLang.all) {
      expect(seen.add(lang.code), isTrue,
          reason: '${lang.code} is listed twice');
      // The shape the engine accepts (engine/src/settings.rs::is_language_tag):
      // a lower-case primary subtag of 2-3 letters, optional region.
      expect(RegExp(r'^[a-z]{2,3}(-[a-z0-9]{2,8})?$').hasMatch(lang.code), isTrue,
          reason: '${lang.code} is not a language tag the engine would store');
    }
  });

  test('every language names itself, once', () {
    final names = <String>{};
    for (final lang in AppLang.all) {
      expect(lang.nativeName.trim(), isNotEmpty);
      expect(lang.nativeName, isNot(lang.code),
          reason: '${lang.code} shows its code instead of its own name');
      expect(lang.englishName.trim(), isNotEmpty);
      expect(names.add(lang.nativeName), isTrue,
          reason: 'two languages share the name ${lang.nativeName}');
    }
  });

  test('direction comes from the language, and both directions are represented',
      () {
    // Arabic is the reason the whole RTL path exists; if this ever flips, the
    // layout assertions in every other test are meaningless.
    expect(AppLang.ar.direction, TextDirection.rtl);
    expect(AppLang.en.direction, TextDirection.ltr);
    expect(AppLang.all.where((l) => l.isRtl), isNotEmpty);
    expect(AppLang.all.where((l) => !l.isRtl), isNotEmpty);
    for (final lang in AppLang.all) {
      expect(lang.isRtl, lang.direction == TextDirection.rtl);
    }
  });

  test('a stored code resolves to a language, and an unknown one does not', () {
    expect(AppLang.byCode('ar'), AppLang.ar);
    expect(AppLang.byCode('en'), AppLang.en);
    // Case and a region are the user's or the engine's business, not ours.
    expect(AppLang.byCode('EN'), AppLang.en);
    expect(AppLang.byCode('en-GB'), AppLang.en);
    expect(AppLang.byCode('pt-br'), isNull,
        reason: 'a tag with no pack must not resolve to some other language');
    expect(AppLang.byCode(null), isNull);
    expect(AppLang.byCode(''), isNull);
  });

  test('the pack loader keys are exactly the bundled codes', () {
    expect(bundledLangs.keys.toSet(), {for (final l in AppLang.all) l.code});
    for (final lang in AppLang.all) {
      expect(bundledLangs[lang.code], lang.nativeName);
    }
  });

  test('lookup falls back to English, then to the key', () {
    final tables = {
      'en': {'a': 'A'},
      'ar': {'a': 'أ'},
    };
    expect(lookup(tables, AppLang.ar, 'a'), 'أ');
    expect(lookup(tables, AppLang.en, 'a'), 'A');
    // A key that only English has still renders in Arabic.
    expect(lookup({'en': {'only': 'Only'}}, AppLang.ar, 'only'), 'Only');
    // And a key nobody has renders as itself, never as an empty string.
    expect(lookup(tables, AppLang.ar, 'missing.key'), 'missing.key');
  });

  test('the packs parse as flat string maps', () {
    for (final lang in AppLang.all) {
      for (final file in _moduleFiles(lang.code)) {
        final raw = File('assets/i18n/${lang.code}/$file').readAsStringSync();
        final decoded = jsonDecode(raw);
        expect(decoded, isA<Map<String, dynamic>>(),
            reason: '${lang.code}/$file is not an object');
        (decoded as Map).forEach((k, v) {
          expect(k, isA<String>());
          expect(v, isA<String>(),
              reason: '${lang.code}/$file: $k is not a string');
        });
      }
    }
  });
}

/// The module files a language actually ships, by file name.
Set<String> _moduleFiles(String code) => Directory('assets/i18n/$code')
    .listSync()
    .whereType<File>()
    .map((f) => f.path.split(Platform.pathSeparator).last)
    .where((name) => name.endsWith('.json'))
    .toSet();