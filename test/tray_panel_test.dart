// The tray panel (D-040), held to the same fake engine the screens are: it is
// the surface a user reaches without a window open, so what it claims about the
// machine has to come from the engine, and what it changes has to go there.
//
// `qa/ui/harness.dart` mounts it outside the router on purpose: the panel has no
// route of its own — it paints over whatever route is up — and its controls are
// still swept and ledgered (`surfaces.trayPanel`) so one cannot be dropped
// unnoticed.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/window/tray_panel.dart';

import '../qa/ui/fake_engine.dart';
import '../qa/ui/harness.dart';

void main() {
  testWidgets('the panel reads the engine for the state it shows', (
    tester,
  ) async {
    final mounted = await openScreen(tester, const TrayPanel());
    expect(tester.takeException(), isNull, reason: 'the panel threw on render');
    await settle(tester);

    // Its three numbers come from the engine, not from the app's own guesses.
    expect(
      mounted.engine.called('guard.status'),
      isTrue,
      reason: 'the panel did not ask the engine about the guard',
    );
    expect(
      mounted.engine.called('fw.default_deny.status'),
      isTrue,
      reason: 'the panel did not ask the engine about the firewall',
    );
    expect(
      mounted.engine.called('net.connections'),
      isTrue,
      reason: 'the panel did not ask the engine about connections',
    );

    // And they are on screen, next to their labels.
    expect(find.text('Guard'), findsOneWidget);
    expect(find.text('Firewall'), findsOneWidget);
    expect(find.text('Connections'), findsOneWidget);
    expect(find.text('Process guard'), findsOneWidget);
  });

  testWidgets('the guard switch asks the engine, and re-reads the answer', (
    tester,
  ) async {
    final mounted = await openScreen(tester, const TrayPanel());
    await settle(tester);
    final reads = mounted.engine.count('guard.status');

    await tester.tap(find.byType(Switch).first);
    await settle(tester);

    expect(
      mounted.engine.called('guard.start') ||
          mounted.engine.called('guard.stop'),
      isTrue,
      reason:
          'the guard switch did not ask the engine: '
          '${mounted.engine.calledMethods}',
    );
    // The switch follows the engine, so the state is read back rather than
    // assumed from the tap.
    expect(
      mounted.engine.count('guard.status'),
      greaterThan(reads),
      reason: 'the switch did not re-read the guard state',
    );
  });

  testWidgets('the panel has no private copy of the settings it toggles', (
    tester,
  ) async {
    final mounted = await openScreen(tester, const TrayPanel());
    await settle(tester);

    // Do not disturb is the second switch; keep-running is the third. Both write
    // the same settings Settings → Protection writes.
    await tester.tap(find.byType(Switch).at(1));
    await settle(tester);
    expect(
      mounted.engine.lastParams('settings.set')?.containsKey('dnd'),
      isTrue,
      reason: 'do-not-disturb wrote something that was not the dnd setting',
    );

    await tester.tap(find.byType(Switch).at(2));
    await settle(tester);
    expect(
      mounted.engine.lastParams('settings.set')?.containsKey('close_to_tray'),
      isTrue,
      reason: 'keep-running wrote something that was not the tray setting',
    );
  });

  testWidgets('the panel closes on Escape and does not throw on Quit', (
    tester,
  ) async {
    await openScreen(tester, const TrayPanel());
    await settle(tester);

    // Escape is the way out of a flyout that has no title bar to click.
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await settle(tester);
    expect(tester.takeException(), isNull);

    await tester.tap(find.text('Quit MI CS completely'));
    await settle(tester);
    // Quit asks the engine it started to stop and then closes the window; with
    // no window_manager to answer (this test) it must still end quietly.
    expect(
      tester.takeException(),
      isNull,
      reason: 'Quit threw instead of ending quietly',
    );
  });

  testWidgets('Quit is a full exit: the engine is stopped, then the window goes', (
    tester,
  ) async {
    final engine = FakeEngine();
    await openScreen(tester, const TrayPanel(), engine: engine);
    await settle(tester);

    // Watch the window channel itself, after the harness installed its
    // catch-all handler, so `destroy` is told apart from every other call.
    final windowCalls = <String>[];
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(
      const MethodChannel('window_manager'),
      (call) async {
        windowCalls.add(call.method);
        return null;
      },
    );
    addTearDown(() => messenger.setMockMethodCallHandler(
        const MethodChannel('window_manager'), null));

    await tester.tap(find.text('Quit MI CS completely'));
    await settle(tester);

    // The label promises the whole app, so the exit has to reach both halves:
    // the engine this app started, and the process that is the window.
    expect(engine.engineStopped, isTrue,
        reason: 'Quit must stop the engine this app started');
    expect(windowCalls, contains('destroy'),
        reason: 'Quit must end the window process');
  });
}
