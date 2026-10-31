import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/features/intel/screens/intel_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// The real language packs, read from disk. Loading them through the asset
/// bundle ties the first frame to when that future happens to resolve, which
/// makes assertions on copy flaky; the parity test is what guards the packs
/// themselves, so here the real strings are enough.
Map<String, Map<String, String>> _loadPacks() {
  final tables = <String, Map<String, String>>{};
  for (final lang in bundledLangs.keys) {
    final table = <String, String>{};
    for (final file in Directory('assets/i18n/$lang').listSync().whereType<File>()) {
      final decoded =
          (jsonDecode(file.readAsStringSync()) as Map).cast<String, dynamic>();
      decoded.forEach((k, v) => table[k] = v.toString());
    }
    tables[lang] = table;
  }
  return tables;
}

class _FixedI18n extends I18nLoader {
  @override
  Future<Map<String, Map<String, String>>> build() async => _loadPacks();
}

/// The Intel screen is a report of what the engine holds (D-012): it must show
/// every source — including the ones that are failing or not configured — with
/// its own numbers, and it must never look "fresh" while offline.
class _FakeIpc extends EngineIpc {
  _FakeIpc({required this.status});
  final Map<String, dynamic> status;
  final requests = <String>[];
  bool syncCalled = false;

  @override
  Stream<Map<String, dynamic>> get progressStream =>
      const Stream<Map<String, dynamic>>.empty();

  @override
  Stream<Map<String, dynamic>> get eventStream =>
      const Stream<Map<String, dynamic>>.empty();

  @override
  Future<dynamic> request(String method,
      [Map<String, dynamic>? params,
      Duration timeout = const Duration(seconds: 120)]) async {
    requests.add(method);
    switch (method) {
      case 'settings.get':
        // English keeps the assertions readable; the copy itself comes from the
        // language packs either way.
        return <String, dynamic>{'lang': 'en'};
      case 'sync.status':
        return status;
      case 'sync.now':
        syncCalled = true;
        return <String, dynamic>{'status': 'success'};
    }
    return <String, dynamic>{};
  }
}

Map<String, dynamic> _status({required bool online}) => <String, dynamic>{
      'online': online,
      'ioc_hash_total': 0,
      'ioc_domain_total': 76737,
      'kev_total': 1764,
      'cve_cache_total': 80,
      'geoip_countries': 0,
      'last_success': online ? 1793313745 : null,
      'age_seconds': online ? 120 : null,
      'sync_interval_hours': 6,
      'sources': <Map<String, dynamic>>[
        {
          'source': 'ioc_domains',
          'network': true,
          'on_demand': false,
          'state': 'ok',
          'age_seconds': 120,
          'seconds_to_due': 21480,
          'failures': 0,
          'items': 76737,
          'detail': '76737 new of 76737 blocked names',
        },
        {
          'source': 'ioc_hashes',
          'network': true,
          'on_demand': false,
          'state': 'not_configured',
          'age_seconds': null,
          'seconds_to_due': 21480,
          'failures': 0,
          'items': 0,
          'detail': 'no hash feed configured',
        },
        {
          'source': 'kev',
          'network': true,
          'on_demand': false,
          'state': 'failed',
          'age_seconds': 90000,
          'seconds_to_due': 900,
          'failures': 3,
          'items': 1764,
          'last_error': 'HTTP 503',
        },
        {
          'source': 'nvd',
          'network': true,
          'on_demand': true,
          'state': 'ok',
          'age_seconds': 600,
          'seconds_to_due': null,
          'failures': 0,
          'items': 80,
          'detail': '4 live NVD lookups (0 from cache, 40 CVEs)',
        },
      ],
    };

Widget _harness(EngineIpc ipc) => ProviderScope(
      overrides: [
        engineIpcProvider.overrideWithValue(ipc),
        i18nProvider.overrideWith(_FixedI18n.new),
      ],
      child: const MaterialApp(home: Scaffold(body: IntelScreen())),
    );

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  /// Mounts the screen in a viewport tall enough to hold every source card.
  /// Nothing here waits on the asset bundle, so the frame count is stable.
  Future<void> open(WidgetTester tester, _FakeIpc ipc) async {
    tester.view.physicalSize = const Size(1400, 2600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(_harness(ipc));
    await tester.pump();
    await tester.pump();
    expect(find.text('Sync now'), findsOneWidget, reason: 'copy did not load');
  }

  testWidgets('every source is reported with its own state and numbers',
      (tester) async {
    final ipc = _FakeIpc(status: _status(online: true));
    await open(tester, ipc);

    expect(ipc.requests, contains('sync.status'));

    // Totals answer "what do I have on this machine".
    expect(find.text('76737'), findsOneWidget);
    expect(find.text('1764'), findsOneWidget);

    // Each source keeps its own story: fresh, unconfigured, failing, on demand.
    expect(find.textContaining('76737 new of 76737 blocked names'),
        findsOneWidget);
    expect(find.textContaining('no hash feed configured'), findsOneWidget);
    expect(find.textContaining('Last error: HTTP 503'), findsOneWidget,
        reason: 'a failing source must name its error, not hide behind totals');
    expect(find.textContaining('4 live NVD lookups'), findsOneWidget);
    expect(find.textContaining('on demand'), findsOneWidget,
        reason: 'NVD is recorded by scans, not scheduled');

    await tester.tap(find.byIcon(Icons.sync));
    await tester.pump();
    expect(ipc.syncCalled, isTrue);
  });

  testWidgets('offline is stated instead of showing a fresh timestamp',
      (tester) async {
    final ipc = _FakeIpc(status: _status(online: false));
    await open(tester, ipc);

    expect(find.text('Offline'), findsOneWidget);
    expect(find.textContaining('feeds are retried'), findsOneWidget);
    expect(find.textContaining('never synced'), findsOneWidget);
  });
}