// Every screen, mounted the way the app mounts it, with a fake engine that
// answers from the contract registry - and then every control under it tapped.
//
// Two claims are being tested, and they fail differently:
//   1. the screen renders and every control it shows can be tapped without an
//      exception, against a fake the contract harness agrees with;
//   2. nothing was silently dropped: the set of controls is compared with
//      `qa/ui/ledger.json`, so a new button (or a deleted one) is a reviewed
//      diff instead of an unnoticed change.
//
// A failure here is usually one of three things: the screen wants a field the
// fixture does not have (add it to `qa/ui/fixtures.json`), the screen calls a
// method the registry has no shape for (that is a contract gap), or the control
// genuinely throws (that is the bug this file exists to find).
//
// Regenerating the ledger after an intended change:
//   $env:UI_LEDGER_WRITE = "1"; flutter test --no-pub test/ui_screens_test.dart
// and commit the diff. Without the variable the file is read-only and a
// mismatch fails the build.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/features/audit/screens/audit_screen.dart';
import 'package:mics_app/features/canaries/screens/canaries_screen.dart';
import 'package:mics_app/features/dashboard/screens/dashboard_screen.dart';
import 'package:mics_app/features/guard/screens/guard_screen.dart';
import 'package:mics_app/features/hardening/screens/hardening_screen.dart';
import 'package:mics_app/features/ids/screens/ids_screen.dart';
import 'package:mics_app/features/incidents/screens/incidents_screen.dart';
import 'package:mics_app/features/intel/screens/intel_screen.dart';
import 'package:mics_app/features/network/screens/network_monitor_screen.dart';
import 'package:mics_app/features/reports/screens/reports_screen.dart';
import 'package:mics_app/features/scanner/screens/scanner_screen.dart';
import 'package:mics_app/features/settings/screens/settings_screen.dart';
import 'package:mics_app/features/vulns/screens/vuln_scanner_screen.dart';

import '../qa/ui/harness.dart';
import '../qa/ui/ledger.dart';

/// The thirteen routes in `lib/core/router/app_router.dart`, in their order.
final Map<String, Widget Function()> screens = {
  'dashboard': () => const DashboardScreen(),
  'audit': () => const AuditScreen(),
  'scanner': () => const ScannerScreen(),
  'network': () => const NetworkMonitorScreen(),
  'ids': () => const IdsScreen(),
  'vulns': () => const VulnScannerScreen(),
  'guard': () => const GuardScreen(),
  'canaries': () => const CanariesScreen(),
  'hardening': () => const HardeningScreen(),
  'incidents': () => const IncidentsScreen(),
  'reports': () => const ReportsScreen(),
  'intel': () => const IntelScreen(),
  'settings': () => const SettingsScreen(),
};

void main() {
  test('the screen list is the router list', () {
    final routes = File('lib/core/router/app_router.dart').readAsStringSync();
    for (final name in screens.keys) {
      expect(routes.contains("'/$name'"), isTrue,
          reason: '$name is not a route in app_router.dart');
    }
    expect(screens.length, 13);
  });

  for (final entry in screens.entries) {
    testWidgets('${entry.key}: renders and every control is tappable',
        (tester) async {
      // A screen that navigates away (`context.go('/hardening')`) lands on a
      // stub route; the sweep comes back so the next control is on this screen.
      final mounted = await openScreen(tester, entry.value(),
          otherRoutes: const ['/hardening']);
      expect(tester.takeException(), isNull,
          reason: '${entry.key} threw while rendering');

      final result = await sweep(tester, mounted);

      expect(mounted.engine.unanswerable, isEmpty,
          reason: '${entry.key} asked for methods neither the fixtures nor the '
              'registry could answer: ${mounted.engine.unanswerable}');
      expect(result.errors, isEmpty,
          reason: '${entry.key}: taps failed\n${result.errors.join('\n')}');
      expect(result.found, isNotEmpty,
          reason: '${entry.key} exposed no interactive control at all');

      await expectLedger('screens.${entry.key}', result.found);
    });
  }

  // Two behaviours that only exist once the engine pushes something: the
  // screens subscribe to `eventStream`/`progressStream`, and a fixture cannot
  // cover a stream by existing.
  testWidgets('scanner: a finished scan replaces the progress with findings',
      (tester) async {
    final mounted = await openScreen(tester, const ScannerScreen());
    final engine = mounted.engine;
    // The screen starts from the persisted job list; the button starts a new
    // scan, which the engine then finishes while the screen is watching.
    await tester.tap(find.text('Scan').first);
    await settle(tester);
    expect(engine.called('scan.start'), isTrue,
        reason: 'the Scan button did not ask the engine for a scan');

    engine.finishRunningScan(findings: 2);
    await settle(tester);
    expect(engine.called('job.get'), isTrue,
        reason: 'a job_finished event did not pull the completed job');
    expect(find.textContaining('Suspicious_Packer'), findsWidgets,
        reason: 'the finished scan did not show its findings');
  });

  testWidgets('guard: a dismiss the engine flags surfaces the mute offer',
      (tester) async {
    final mounted = await openScreen(tester, const GuardScreen());
    final engine = mounted.engine;
    expect(find.byTooltip('Dismiss'), findsOneWidget,
        reason: 'the pushed alert did not reach the screen');

    // The engine decides when a category has been dismissed enough times; the
    // screen only offers the mute when it says so.
    await tester.tap(find.byTooltip('Dismiss'));
    await settle(tester);
    expect(engine.called('guard.event.dismiss'), isTrue);
    expect(find.text('Mute'), findsOneWidget,
        reason: 'mute_suggested from the engine did not offer the mute');

    await tester.tap(find.text('Mute'));
    await settle(tester);
    expect(engine.called('noise.mute'), isTrue,
        reason: 'the mute button did not reach noise.mute');
    expect(engine.lastParams('noise.mute'),
        {'category': 'guard_alert:guard-002'},
        reason: 'the mute was for the wrong category');
  });
}