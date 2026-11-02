// The shell is UI too: the navigation rail, the title bar with the window
// buttons and the language toggle, the engine chip and the command box. They
// are not inside any of the thirteen screens, so the screen sweep never touches
// them.
//
// The shell is a desktop window, so the window/tray plugin channels are mocked
// (qa/ui/harness.dart): without an answer the minimise button throws
// MissingPluginException, and a test that cannot tell a broken button from a
// missing plugin is not worth writing.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/features/shell/app_shell.dart';

import '../qa/ui/harness.dart';
import '../qa/ui/ledger.dart';

/// Every route the rail can navigate to, so a tap lands somewhere.
const _routes = [
  '/dashboard',
  '/audit',
  '/scanner',
  '/network',
  '/ids',
  '/vulns',
  '/guard',
  '/canaries',
  '/hardening',
  '/incidents',
  '/reports',
  '/intel',
  '/settings',
];

void main() {
  test('the rail knows every route in app_router.dart', () {
    final routes = File('lib/core/router/app_router.dart').readAsStringSync();
    for (final path in _routes) {
      expect(routes.contains("'$path'"), isTrue,
          reason: '$path is not a route in app_router.dart');
    }
  });

  testWidgets('shell: every rail item, window button and command box is usable',
      (tester) async {
    final mounted = await openScreen(
        tester, const AppShell(child: Scaffold(body: Text('child'))),
        otherRoutes: _routes);
    expect(tester.takeException(), isNull,
        reason: 'the shell threw while rendering');
    // One card, so the sweep taps the surface this phase added: the card body
    // (which opens the screen that explains it) and its close button.
    mounted.engine.fileCrashReport();
    await settle(tester);

    final result = await sweep(tester, mounted);

    expect(mounted.engine.unanswerable, isEmpty,
        reason: 'the shell asked for methods the fake could not answer: '
            '${mounted.engine.unanswerable}');
    expect(result.errors, isEmpty,
        reason: 'shell taps failed\n${result.errors.join('\n')}');
    // Every rail destination must be reachable by name: a label that is a
    // number or an icon code point means the rail item lost its text.
    for (final path in ['Dashboard', 'Settings', 'Intelligence']) {
      expect(result.found.any((c) => c.contains(path)), isTrue,
          reason: 'the rail no longer shows "$path": ${result.found}');
    }
    // The card is a control pair, not decoration: its close button is named by
    // what it does.
    expect(result.tapped.any((c) => c.startsWith('IconButton(Dismiss')),
            isTrue,
        reason: 'the card cannot be closed: ${result.tapped}');
    expect(result.tapped.any((c) => c.startsWith('InkWell(')), isTrue,
        reason: 'the card cannot be opened: ${result.tapped}');

    await expectLedger('shell', result.found);
  });

  testWidgets('shell: an alert card sits in the bottom corner, and swaps side '
      'with the writing direction', (tester) async {
    final mounted = await openScreen(
        tester, const AppShell(child: Scaffold(body: Text('child'))),
        otherRoutes: _routes);
    const cards = ValueKey('alert-cards');
    expect(find.byKey(cards), findsNothing,
        reason: 'an alert card is on screen with nothing to say');

    mounted.engine.fileCrashReport();
    await settle(tester);

    // The bug id, not a paraphrase of it: it is what a user reads out to
    // whoever supports the build (and it is the same string in both languages).
    expect(find.text('MICS-20261102-0d9743'), findsOneWidget);
    final ltr = tester.getRect(find.byKey(cards));
    final view = tester.view.physicalSize.width / tester.view.devicePixelRatio;
    expect(ltr.width, 340);
    expect(ltr.right, closeTo(view - 18, 0.5),
        reason: 'LTR keeps the card in the right-hand corner: $ltr');
    expect(ltr.bottom, closeTo(2400 - 18, 0.5));

    // Arabic writes right-to-left, so the same corner is the left one. The
    // shell reads the direction, never the language name.
    await mounted.container.read(settingsProvider.notifier).setLang(AppLang.ar);
    await settle(tester);
    final rtl = tester.getRect(find.byKey(cards));
    expect(rtl.left, closeTo(18, 0.5),
        reason: 'RTL puts the card in the left-hand corner: $rtl');

    // Closing it removes it, and closing it twice is not an error.
    expect(rtl.width, 340);
    await tester.tap(find.descendant(
        of: find.byKey(cards), matching: find.byType(IconButton)));
    await settle(tester);
    expect(find.byKey(cards), findsNothing);
    expect(find.text('MICS-20261102-0d9743'), findsNothing);
  });
}