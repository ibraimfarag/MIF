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

    await expectLedger('shell', result.found);
  });
}