// Settings -> About is where the whole ج2 slice answers its question: "is this
// copy the one that was published?". The engine reports `status.integrity` in
// three words (D-025), so this mounts the real screen against a fake engine that
// says each of them - and against one that says nothing at all, because a screen
// that guesses a verdict is worse than one that stays quiet.

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/features/settings/screens/settings_screen.dart';

import '../qa/ui/fake_engine.dart';
import '../qa/ui/harness.dart';

/// The committed fixtures, with a `status` reply carrying the verdict under
/// test. `null` leaves the field out, which is what a build with no manifest (and
/// any engine older than ج2) looks like on the wire.
FakeEngine engineSaying(String? integrity) {
  final decoded =
      (jsonDecode(File('qa/ui/fixtures.json').readAsStringSync()) as Map)
          .cast<String, dynamic>();
  final methods = (decoded['methods'] as Map).cast<String, dynamic>();
  final status = <String, dynamic>{
    ...?(methods['status'] as Map?)?.cast<String, dynamic>(),
  };
  if (integrity != null) status['integrity'] = integrity;
  methods['status'] = status;
  return FakeEngine(fixtures: methods);
}

/// Mounts Settings and scrolls to the About card at the bottom of the page.
///
/// The screen is a lazy list: the last section is not built until the page is
/// scrolled to it, so a test that only pumps the first frame asserts against a
/// tree the user never sees.
Future<Mounted> openAbout(WidgetTester tester, String? integrity) async {
  final mounted = await openScreen(tester, const SettingsScreen(),
      engine: engineSaying(integrity));
  await tester.drag(find.byType(Scrollable).first, const Offset(0, -4000));
  await settle(tester);
  return mounted;
}

/// The About line for [key], in English (the harness mounts the `en` pack).
String aboutLine(Mounted mounted, String key) =>
    mounted.container.read(i18nProvider).value!['en']![key]!;

void main() {
  for (final pair in const [
    ['ok', 'settings.integrityOk'],
    ['untrusted-certificate', 'settings.integrityUntrusted'],
    ['unverified', 'settings.integrityUnverified'],
  ]) {
    testWidgets('About says what the engine reported: ${pair[0]}',
        (tester) async {
      final mounted = await openAbout(tester, pair[0]);
      expect(find.text(aboutLine(mounted, pair[1])), findsOneWidget,
          reason: 'the engine said "${pair[0]}" and About did not say '
              '${pair[1]}');
      for (final other in const [
        'settings.integrityOk',
        'settings.integrityUntrusted',
        'settings.integrityUnverified',
      ]) {
        if (other == pair[1]) continue;
        expect(find.text(aboutLine(mounted, other)), findsNothing,
            reason: 'About showed two verdicts at once');
      }
    });
  }

  testWidgets('About claims no verdict when the engine sent none',
      (tester) async {
    final mounted = await openAbout(tester, null);
    for (final key in const [
      'settings.integrityOk',
      'settings.integrityUntrusted',
      'settings.integrityUnverified',
    ]) {
      expect(find.text(aboutLine(mounted, key)), findsNothing,
          reason: 'a copy that was told nothing must not claim $key');
    }
  });
}
