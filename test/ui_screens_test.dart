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
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/window/tray_panel.dart';
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

import '../qa/ui/fake_engine.dart';
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

/// Surfaces that are not routes. The tray panel (D-040) is one: it paints over
/// whatever route is up rather than having a page of its own, but its controls
/// are exactly as droppable as a screen's — so it is swept and ledgered like
/// one, under its own key.
final Map<String, Widget Function()> surfaces = {
  'trayPanel': () => const TrayPanel(),
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

  for (final entry in surfaces.entries) {
    testWidgets('${entry.key}: renders and every control is tappable',
        (tester) async {
      final mounted = await openScreen(tester, entry.value());
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

      await expectLedger('surfaces.${entry.key}', result.found);
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

  // The language lives in Settings now, and it is more than a string: it picks
  // the pack, it tells the engine what to store, and it decides which way the
  // whole tree runs. All three are asserted here because a dropdown that only
  // changes the label would pass a screenshot test.
  testWidgets('settings: the language dropdown switches pack, direction and engine',
      (tester) async {
    final mounted = await openScreen(tester, const SettingsScreen());
    expect(find.text('Language'), findsOneWidget,
        reason: 'the language picker is not in Settings');
    expect(Directionality.of(tester.element(find.text('Language'))),
        TextDirection.ltr);

    await tester.tap(find.byType(DropdownButton<AppLang>));
    await settle(tester);
    await tester.tap(find.text('العربية').last);
    await settle(tester);

    expect(mounted.engine.lastParams('settings.set'), {'lang': 'ar'},
        reason: 'the chosen language never reached the engine');
    expect(find.text('اللغة'), findsOneWidget,
        reason: 'the screen did not switch to the Arabic pack');
    expect(find.text('Language'), findsNothing);
    expect(Directionality.of(tester.element(find.text('اللغة'))),
        TextDirection.rtl,
        reason: 'an RTL language must lay the tree out right-to-left');
    expect(mounted.container.read(rtlProvider), isTrue);
  });

  // The tag nobody can pick: `settings.json` edited by hand, or an RPC caller
  // writing `lang` straight. The screen used to render Arabic - the product's
  // default - over an English key table, with nothing saying why (D-049).
  testWidgets('settings: a stored tag with no pack renders English and is named',
      (tester) async {
    final mounted = await openScreen(tester, const SettingsScreen(),
        engine: FakeEngine(initialLang: 'de'));

    expect(find.text('Language'), findsOneWidget,
        reason: 'an unrenderable tag must fall back to the English pack');
    expect(find.text('اللغة'), findsNothing);
    expect(Directionality.of(tester.element(find.text('Language'))),
        TextDirection.ltr);
    expect(mounted.container.read(rtlProvider), isFalse);
    expect(find.textContaining('«de»'), findsOneWidget,
        reason: 'nothing on the screen names the tag the engine holds');

    // The picker is the way out of it, and it replaces the tag.
    await tester.tap(find.byType(DropdownButton<AppLang>));
    await settle(tester);
    await tester.tap(find.text('العربية').last);
    await settle(tester);
    expect(mounted.engine.lastParams('settings.set'), {'lang': 'ar'});
    expect(find.text('اللغة'), findsOneWidget);
    expect(find.textContaining('«de»'), findsNothing,
        reason: 'the notice outlived the tag it was reporting');
    expect(mounted.container.read(rtlProvider), isTrue);
  });

  // The scan schedule (و1, D-027). The engine owns the timer, so the only thing
  // the UI can get wrong is the write: an interval the engine would refuse, a
  // dropdown that shows a value it did not store, or a folder that never leaves
  // the screen. All three are asserted against what the fake engine received.
  testWidgets('settings: the scheduled-scan dropdown and folder reach the engine',
      (tester) async {
    final mounted = await openScreen(tester, const SettingsScreen());
    final engine = mounted.engine;

    // Off is the default, and the control has to say so.
    expect(find.text('Scheduled scan'), findsOneWidget,
        reason: 'the schedule is not in Settings');
    expect(find.text('Off'), findsOneWidget,
        reason: 'the dropdown must show the default (off) state');

    await tester.ensureVisible(find.text('Scheduled scan'));
    await settle(tester);
    // Two int dropdowns live on this screen (the intel refresh cadence is the
    // other), so the scan one is found through its own row rather than by index.
    final scanRow = find
        .ancestor(of: find.text('Scheduled scan'), matching: find.byType(Row))
        .first;
    final scanDropdown =
        find.descendant(of: scanRow, matching: find.byType(DropdownButton<int>));
    expect(scanDropdown, findsOneWidget);
    await tester.tap(scanDropdown);
    await settle(tester);
    await tester.tap(find.text('24 h').last);
    await settle(tester);
    expect(engine.lastParams('settings.set'), {'scan_interval_hours': 24},
        reason: 'the chosen interval never reached the engine');
    expect(find.text('24 h'), findsOneWidget,
        reason: 'the dropdown did not keep the value it stored');

    // The folder field: empty is what the engine reads as "the profile folder",
    // so the hint has to be on screen and the field has to exist next to it.
    expect(find.widgetWithText(TextField, 'Empty = your profile folder'),
        findsOneWidget,
        reason: 'the folder field is not on screen');
  });

  // The bug-id surface (ز2-ج). The id on screen has to be the id the engine
  // reported - not a string the screen invented - and the text the user copies
  // has to start with it, because that text is the one thing a user hands to
  // whoever supports the build.
  testWidgets('settings: the diagnostics list shows and copies the engine id',
      (tester) async {
    final clipboard = <String>[];
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        clipboard.add('${(call.arguments as Map)['text']}');
      }
      return null;
    });
    addTearDown(() =>
        messenger.setMockMethodCallHandler(SystemChannels.platform, null));

    final mounted = await openScreen(tester, const SettingsScreen());
    final engine = mounted.engine;
    const id = 'MICS-20261102-0d9743';

    // The list came from the engine's `crash.list`, and both of its reports are
    // on screen (the newest first, as the engine orders them). The section sits
    // below the fold, so the taps scroll to it first.
    expect(engine.called('crash.list'), isTrue,
        reason: 'Diagnostics never asked the engine for its reports');
    await tester.ensureVisible(find.text(id));
    await settle(tester);
    expect(find.text(id), findsOneWidget,
        reason: 'the report the engine listed is not on screen');
    expect(find.text('MICS-20261101-a1b2c3'), findsOneWidget,
        reason: 'the second report the engine listed is not on screen');

    // Opening a row is `crash.get`, for that row's id.
    await tester.tap(find.text(id));
    await settle(tester);
    expect(engine.lastParams('crash.get'), {'bug_id': id},
        reason: 'opening a report did not ask for that report');
    expect(find.textContaining('last request: scan.start'), findsWidgets,
        reason: 'the opened report does not say what happened');

    // Copying puts the paste text on the clipboard, bug id first.
    await tester.ensureVisible(find.byTooltip('Copy report'));
    await tester.tap(find.byTooltip('Copy report'));
    await settle(tester);
    expect(clipboard, isNotEmpty, reason: 'copy never reached the clipboard');
    expect(clipboard.last.startsWith(id), isTrue,
        reason: 'the pasted text must start with the bug id, got:\n'
            '${clipboard.last}');
    expect(clipboard.last, contains('engine log lines'),
        reason: 'the pasted text dropped the log tail the report carries');

    // Deleting asks the engine for that id, and the row goes away because the
    // list was re-read, not because the screen hid it.
    await tester.ensureVisible(find.byTooltip('Delete report'));
    await tester.tap(find.byTooltip('Delete report'));
    await settle(tester);
    expect(engine.lastParams('crash.delete'), {'bug_id': id});
    expect(find.text(id), findsNothing,
        reason: 'the deleted report is still on screen');
    expect(find.text('MICS-20261101-a1b2c3'), findsOneWidget,
        reason: 'deleting one report removed another');
  });

  // The engine's refusal has to reach the user. It is printed on a stderr the
  // detached spawn throws away, which is why "engine missing" used to arrive
  // with no reason and a retry that could not succeed; `EngineIpc` re-runs the
  // engine once to recover the sentence, and the Settings → Engine section shows
  // it. Nothing about the sentence is a fixture: this is the real copy.
  testWidgets('settings: a refused start shows the engine\'s own reason',
      (tester) async {
    await openScreen(
      tester,
      const SettingsScreen(),
      engine: _RefusingEngine(),
    );
    expect(find.text(_RefusingEngine.refusal), findsOneWidget,
        reason: 'the engine said why it would not start and the app did not '
            'show it');
    expect(find.text('Why it would not start'), findsOneWidget,
        reason: 'the reason is on screen with no label saying what it is');
  });

  // The same screen with a healthy engine: the reason line is not a permanent
  // fixture of Settings, so a start that works must leave nothing behind.
  testWidgets('settings: a running engine shows no failure line',
      (tester) async {
    await openScreen(tester, const SettingsScreen());
    expect(find.text('Why it would not start'), findsNothing,
        reason: 'a running engine is being reported as a failed start');
  });
}

/// The engine refused to start and said why — `FakeEngine` answers everything
/// else from the fixture, so the rest of the screen renders its steady state.
class _RefusingEngine extends FakeEngine {
  static const refusal =
      'MI CS was started from a Low-integrity location: it cannot write its '
      'state database ("attempt to write a readonly database") or reach the '
      'privileged helper';

  @override
  EngineState get state => EngineState.engineMissing;

  @override
  String? get lastFailure => refusal;

  @override
  Stream<EngineState> get statusStream =>
      Stream<EngineState>.value(EngineState.engineMissing);
}