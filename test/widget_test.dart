import 'dart:ui';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/main.dart';

/// Never spawns the real engine inside tests.
class FakeIpc extends EngineIpc {
  @override
  Future<bool> ensureRunning() async => false;

  @override
  EngineState get state => EngineState.stopped;

  @override
  Stream<EngineState> get statusStream => const Stream.empty();

  @override
  String resolveEnginePath() => 'fake-engine.exe';

  @override
  void dispose() {}
}

void main() {
  testWidgets('app boots to shell', (tester) async {
    tester.view.physicalSize = const Size(1600, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(ProviderScope(
      overrides: [engineIpcProvider.overrideWithValue(FakeIpc())],
      child: const MicsApp(),
    ));
    await tester.pump();
    expect(find.byType(MicsApp), findsOneWidget);
  });
}
