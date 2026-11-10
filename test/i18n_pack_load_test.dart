// The pack loader tolerates a module it cannot read - a language that has not
// been translated yet must not break the app - and that tolerance used to cover
// a *whole* missing folder as well: a language in `AppLang.all` whose folder
// `pubspec.yaml` does not declare loaded as an empty table, with nothing logged
// and nothing failing (the LOW row in `docs/TODO.md` §7, closed by D-050). The
// two cases are told apart now, and the build defect is named in the log and on
// the Settings screen.
//
// The first case reads the *real* bundle through the loader the app runs, so a
// `pubspec.yaml` that loses a language folder fails here rather than on a user's
// screen; the rest drive the loader with a reader that refuses exactly what the
// asset list would refuse.
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';

/// The asset bundle as far as one language is concerned: any file whose folder
/// is not in [folders] throws, which is what `pubspec.yaml` forgetting
/// `assets/i18n/<code>/` looks like from inside the loader.
PackReader _onlyIn(Set<String> folders) => (path) async {
      final folder = path.split('/')[2];
      if (!folders.contains(folder)) {
        throw StateError('not in the asset list: $path');
      }
      return File(path).readAsString();
    };

/// Loads the packs once, collecting whatever the loader logged.
Future<(Map<String, Map<String, String>>, List<String>, List<PackLoad>)> _load(
    PackReader read) async {
  final logged = <String>[];
  final container = ProviderContainer(overrides: [
    i18nProvider.overrideWith(() => I18nLoader(read: read, log: logged.add)),
  ]);
  addTearDown(container.dispose);
  final tables = await container.read(i18nProvider.future);
  return (tables, logged, container.read(i18nProvider.notifier).loads);
}

void main() {
  testWidgets('the real bundle loads every bundled language and logs nothing',
      (tester) async {
    // Default reader, default sink: this is the loader the app builds, reading
    // the asset list this repository declares. Empty on any language here means
    // a folder is missing from `pubspec.yaml` - the defect the row is about.
    final logged = <String>[];
    final container = ProviderContainer(
        overrides: [i18nProvider.overrideWith(() => I18nLoader(log: logged.add))]);
    addTearDown(container.dispose);

    final tables = await container.read(i18nProvider.future);

    for (final lang in AppLang.all) {
      expect(packLoaded(tables, lang.code), isTrue,
          reason: 'assets/i18n/${lang.code}/ loaded nothing - is the folder '
              'still declared in pubspec.yaml "assets:"?');
    }
    expect(logged, isEmpty,
        reason: 'a correct build must not log: $logged');
    expect(container.read(i18nProvider.notifier).loads.every((l) => l.complete),
        isTrue);
  });

  test('a folder the asset list does not carry loads empty, is named, and stays alive',
      () async {
    final (tables, logged, loads) = await _load(_onlyIn({'ar'}));

    // The symptom the row names: the table is empty, so every key falls back.
    expect(tables['en'], isEmpty);
    expect(packLoaded(tables, 'en'), isFalse);
    expect(lookup(tables, AppLang.en, 'settings.title'), 'settings.title',
        reason: 'with no English pack the key surfaces as its own name');

    // The tolerance that must survive the fix: the other language is intact,
    // and the loader resolves a value instead of throwing - `lib/main.dart`
    // gates the first frame on this provider ever having a value, so a throw
    // here would be a splash screen that never ends.
    expect(packLoaded(tables, 'ar'), isTrue);
    expect(lookup(tables, AppLang.ar, 'settings.title'), isNot('settings.title'));

    // And the defect is reported instead of swallowed: one line, naming the
    // folder and the asset list. This is the half the row says was missing.
    expect(logged, hasLength(1), reason: 'expected exactly one line, got $logged');
    expect(logged.single, contains('assets/i18n/en/'));
    expect(logged.single, contains('no pack loaded'));

    final en = loads.singleWhere((l) => l.code == 'en');
    final ar = loads.singleWhere((l) => l.code == 'ar');
    expect(en.nothingLoaded, isTrue);
    expect(en.failed, i18nModules.length);
    expect(en.firstFailure, 'assets/i18n/en/${i18nModules.first}.json');
    expect(ar.complete, isTrue);
  });

  test('one unread module is tolerated and logged as a gap, not as a missing pack',
      () async {
    final missing = 'assets/i18n/ar/${i18nModules.first}.json';
    final (tables, logged, loads) = await _load(
        (path) async => path == missing
            ? throw StateError('not in the asset list: $path')
            : File(path).readAsString());

    // The deliberate half: a module nobody has translated yet changes nothing
    // about the app's behaviour, and the table keeps the modules that loaded.
    expect(packLoaded(tables, 'ar'), isTrue);
    expect(tables['ar']!.length, lessThan(tables['en']!.length));

    // The other half: it is still a fact, worded apart from a missing folder.
    expect(logged, hasLength(1));
    expect(logged.single, contains('1 of ${i18nModules.length} module(s)'));
    expect(logged.single, contains(missing));
    expect(logged.single, isNot(contains('no pack loaded')));

    expect(loads.singleWhere((l) => l.code == 'ar').complete, isFalse);
    expect(loads.singleWhere((l) => l.code == 'en').complete, isTrue);
  });

  test('the note is null only when every module loaded', () {
    const complete = PackLoad('ar', 20, 0, null);
    const partial = PackLoad('ar', 20, 1, 'assets/i18n/ar/app.json');
    const missing = PackLoad('en', 20, 20, 'assets/i18n/en/app.json');

    expect(i18nPackLoadNote(complete), isNull);
    expect(i18nPackLoadNote(partial), contains('1 of 20'));
    expect(i18nPackLoadNote(missing), contains('no pack loaded'));
    expect(partial.nothingLoaded, isFalse);
    expect(missing.nothingLoaded, isTrue);
    expect(i18nPackLoadNote(missing), isNot(i18nPackLoadNote(partial)));
  });
}
