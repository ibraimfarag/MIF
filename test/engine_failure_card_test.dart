// The wall the owner hit, pinned at both ends.
//
// The engine refuses on purpose when this app starts it from a folder Windows
// labels Low integrity, writes the reason to a stderr nobody reads, and the
// window showed only "EngineException(-1): engine not running" with a retry
// button that could not succeed. `EngineIpc.lastFailure` has held the engine's
// own sentence all along; what was missing was the classifier that recognises it
// and the card that shows it. Both halves are here, so neither can be dropped
// silently later.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/features/dashboard/screens/dashboard_screen.dart';

import '../qa/ui/fake_engine.dart';
import '../qa/ui/harness.dart';

/// The engine's refusal, copied verbatim from an engine started inside the FlyEnv
/// web root: the ERROR line it prints before exiting.
const engineRefusal = 'MI CS was started from a Low-integrity location '
    r'(H:\FlyEnv\PhpWebStudy-Data\server\www\MIF\dist\MICS-portable\mics-engine.exe). '
    'Windows gives process label of folder its image is in, and this one is below '
    'Medium, so engine cannot write its state database ("attempt to write a '
    'readonly database") or reach privileged helper ("installed but not answering")';

/// An engine that never comes up, with [reason] as whatever it managed to say.
class _RefusedEngine extends FakeEngine {
  _RefusedEngine({this.reason = engineRefusal}) : super(initialLang: 'ar');
  final String? reason;

  @override
  String? get lastFailure => reason;

  @override
  EngineState get state => EngineState.engineMissing;

  /// Every request fails the way the audit's does when the pipe never opened.
  @override
  Future<dynamic> request(String method,
          [Map<String, dynamic>? params,
          Duration timeout = const Duration(seconds: 120)]) async =>
      throw EngineException('engine not running');
}

/// The pack's wording for [key], per language. Asserting on these proves the card
/// renders the *pack*, not a literal typed into the widget.
List<String> _packValues(String key) => ['ar', 'en']
    .map((lang) => (jsonDecode(File('assets/i18n/$lang/engine.json')
        .readAsStringSync()) as Map)[key] as String)
    .toList();

/// The Arabic wording for [key] — the language these tests start the app in, so
/// what is asserted is the sentence the user reads.
String _ar(String key) => _packValues(key).first;

void main() {
  group('classifyEngineFailure', () {
    test('names the Low-integrity refusal', () {
      expect(
          classifyEngineFailure(engineRefusal), EngineFailureKind.lowIntegrity);
    });

    test('prefers the folder over the symptom it quotes', () {
      // The refusal also quotes "readonly database"; the folder is the half the
      // user can act on, so it has to win.
      expect(
          classifyEngineFailure('started from a Low-integrity location: '
              '"attempt to write a readonly database"'),
          EngineFailureKind.lowIntegrity);
    });

    test('and the lines this app writes itself', () {
      expect(
          classifyEngineFailure(
              r'mics-engine.exe is not at C:\a\mics-engine.exe'),
          EngineFailureKind.engineMissing);
      expect(
          classifyEngineFailure(
              'the engine could not be started (ProcessException: denied)'),
          EngineFailureKind.spawnFailed);
      expect(classifyEngineFailure(r'C:\a is not writable by this process'),
          EngineFailureKind.dataDirUnwritable);
    });

    test('says nothing when there is nothing to add', () {
      expect(classifyEngineFailure(null), isNull);
      expect(classifyEngineFailure(''), isNull);
      expect(classifyEngineFailure('engine connection lost'), isNull);
    });
  });

  group('the missing-engine card', () {
    testWidgets('shows the reason and the way out, above the symptom',
        (tester) async {
      await openScreen(tester, const DashboardScreen(),
          engine: _RefusedEngine(), i18n: FixedI18n.new);
      await settle(tester);

      expect(find.text(_ar('engine.fail.lowIntegrity')), findsOneWidget,
          reason: "the engine's own reason is on screen");
      expect(find.text(_ar('engine.fail.lowIntegrity.fix')), findsOneWidget,
          reason: 'and the way out of it');
      // The raw symptom is kept verbatim: it is what a bug report needs.
      expect(find.textContaining('engine not running'), findsOneWidget);
    });

    testWidgets('stays as it was when the client has nothing on record',
        (tester) async {
      await openScreen(tester, const DashboardScreen(),
          engine: _RefusedEngine(reason: null), i18n: FixedI18n.new);
      await settle(tester);

      expect(find.textContaining('engine not running'), findsOneWidget);
      expect(find.text(_ar('engine.fail.lowIntegrity')), findsNothing);
      expect(find.text(_ar('engine.fail.lowIntegrity.fix')), findsNothing);
    });
  });
}
