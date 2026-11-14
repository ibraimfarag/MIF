import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/handoff.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/features/scanner/screens/scanner_screen.dart';

import '../qa/ui/fake_engine.dart';
import '../qa/ui/harness.dart';

/// An engine that cannot be asked anything: every request fails, which is what
/// an engine too old to know `app.activate` looks like from the app's side.
class _SilentEngine extends EngineIpc {
  @override
  Future<dynamic> request(String method,
          [Map<String, dynamic>? params,
          Duration timeout = const Duration(seconds: 120)]) async =>
      throw EngineException('engine not running');
}

/// The Explorer verb and the single-instance handoff (D-041): what the command
/// line means, what a second process does with it, and what the window that is
/// already open shows.
void main() {
  group('the --scan argument', () {
    test('is the path Explorer quoted after the flag', () {
      expect(
        AppHandoff.scanPathFrom([r'--scan', r'C:\Users\me\Downloads\a b.pdf']),
        r'C:\Users\me\Downloads\a b.pdf',
      );
    });

    test('survives the equals spelling', () {
      expect(AppHandoff.scanPathFrom([r'--scan=C:\tmp\x.zip']), r'C:\tmp\x.zip');
    });

    test('is null for a plain launch — a second one just comes forward', () {
      expect(AppHandoff.scanPathFrom([]), isNull);
      expect(AppHandoff.scanPathFrom(['--other', 'thing']), isNull);
    });

    test('is null when the flag has no path behind it', () {
      expect(AppHandoff.scanPathFrom(['--scan']), isNull);
      expect(AppHandoff.scanPathFrom(['--scan', '   ']), isNull);
      expect(AppHandoff.scanPathFrom(['--scan=']), isNull);
    });

    test('ignores what comes after the path', () {
      expect(
        AppHandoff.scanPathFrom([r'--scan', r'C:\tmp\a.txt', '--verbose']),
        r'C:\tmp\a.txt',
      );
    });
  });

  group('a second process asks the engine who is there', () {
    test('nobody: it is the window, and nothing was handed over', () async {
      final engine = FakeEngine();
      final seen = <String?>[];
      final handoff = AppHandoff(ipc: engine, onActivate: seen.add);

      expect(await handoff.announce(path: r'C:\tmp\a.txt'), isFalse);
      expect(engine.lastParams('app.activate'), {'path': r'C:\tmp\a.txt'});
      expect(seen, isEmpty, reason: 'the caller acts on its own answer');
    });

    test('the question carries no path for a plain launch', () async {
      final engine = FakeEngine();
      final handoff =
          AppHandoff(ipc: engine, onActivate: (String? _) {});
      await handoff.announce();
      expect(engine.lastParams('app.activate'), isEmpty);
    });

    test('an engine that cannot answer leaves this process as the window',
        () async {
      // An engine too old to know `app.activate`, or one that went away while
      // the app was booting. The user must still get a window, so a failed ask
      // answers "I am the window" — the other way round would mean no window
      // at all and no way to ask for one.
      final seen = <String?>[];
      final handoff = AppHandoff(ipc: _SilentEngine(), onActivate: seen.add);

      expect(await handoff.announce(path: r'C:\tmp\a.txt'), isFalse);
      expect(seen, isEmpty, reason: 'the caller acts on its own answer');
    });

    test('a window: it is handed over, and ends without acting on its own '
        'activation', () async {
      final engine = FakeEngine(fixtures: {
        'app.activate': {'delivered': true},
      });
      final seen = <String?>[];
      final handoff = AppHandoff(ipc: engine, onActivate: seen.add);
      handoff.listen();

      expect(await handoff.announce(path: r'C:\tmp\a.txt'), isTrue);
      // The engine broadcasts to every client, this process included: the
      // window that took the handover is the one that scans.
      engine.emitEvent({
        'type': 'activate',
        'data': {'path': r'C:\tmp\a.txt'},
      });
      await Future<void>.delayed(Duration.zero);
      expect(seen, isEmpty);
    });
  });

  group('the window that is already open', () {
    test('acts on an activation that carries a path', () async {
      final engine = FakeEngine();
      final seen = <String?>[];
      final handoff = AppHandoff(ipc: engine, onActivate: seen.add);
      handoff.listen();

      engine.emitEvent({
        'type': 'activate',
        'data': {'path': r'C:\tmp\a.txt'},
      });
      await Future<void>.delayed(Duration.zero);
      expect(seen, [r'C:\tmp\a.txt']);
    });

    test('comes forward without scanning when there is no path', () async {
      final engine = FakeEngine();
      final seen = <String?>[];
      final handoff = AppHandoff(ipc: engine, onActivate: seen.add);
      handoff.listen();

      engine.emitEvent({'type': 'activate', 'data': {'path': null}});
      engine.emitEvent({'type': 'job_finished', 'data': {'job_id': 'scan-1'}});
      await Future<void>.delayed(Duration.zero);
      expect(seen, [null]);
    });
  });

  testWidgets('a handover scans and the scanner shows the folder it brought',
      (tester) async {
    final engine = FakeEngine();
    final mounted =
        await openScreen(tester, const ScannerScreen(), engine: engine);
    expect(engine.called('scan.start'), isFalse);

    mounted.container.read(handedScanProvider.notifier).handOver(
          r'C:\Users\me\Downloads\report.pdf',
        );
    await settle(tester);

    expect(engine.lastParams('scan.start'), {
      'path': r'C:\Users\me\Downloads\report.pdf',
      'quarantine': true,
    });
    expect(find.text(r'C:\Users\me\Downloads\report.pdf'), findsWidgets);
  });

  test('a handover that arrived before the scanner existed is still scanned',
      () async {
    // The handover can land before the scanner is ever built: main decides which
    // window this is, and the scanner screen mounts whenever the user gets to
    // it. Acting on that earlier value inside `build` is the trap this covers -
    // riverpod has not initialised `state` while a notifier is still building,
    // so the scan threw and the handed path was dropped on the floor.
    final engine = FakeEngine();
    final container = ProviderContainer(
      overrides: [engineIpcProvider.overrideWithValue(engine)],
    );
    addTearDown(container.dispose);

    container.read(handedScanProvider.notifier).handOver(r'C:\tmp\a.pdf');
    container.read(scannerProvider);
    await Future<void>.delayed(Duration.zero);

    expect(engine.lastParams('scan.start'), {
      'path': r'C:\tmp\a.pdf',
      'quarantine': true,
    });
  });
}
