import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/features/network/screens/network_monitor_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// One-click block from the connection list (D-043).
///
/// The click has to send the spec the **engine** built, not one assembled from
/// what the row displays: the image path and the peer port are what the filter
/// matches, and the engine is the only side that saw them. So this stands in for
/// the engine, answers `net.connections` with rows that carry a spec and rows
/// that do not, and records what the UI sends back.
class _FakeIpc extends EngineIpc {
  final requests = <String>[];
  final calls = <Map<String, dynamic>>[];

  /// The BFE refuses a write without an administrator: the default answer here,
  /// because that is what the QA sweep runs into and what the UI must report
  /// instead of a silent success.
  bool refuse = true;

  @override
  Stream<Map<String, dynamic>> get eventStream => const Stream.empty();

  @override
  Stream<Map<String, dynamic>> get progressStream => const Stream.empty();

  @override
  Future<dynamic> request(String method,
      [Map<String, dynamic>? params,
      Duration timeout = const Duration(seconds: 120)]) async {
    requests.add(method);
    if (params != null) calls.add(<String, dynamic>{'method': method, 'params': params});
    switch (method) {
      case 'net.connections':
        return <Map<String, dynamic>>[
          <String, dynamic>{
            'local_address': '192.168.1.20:51544',
            'remote_address': '93.184.216.34:443',
            'protocol': 'TCP',
            'state': 'ESTABLISHED',
            'process_name': 'chrome.exe',
            'process_id': 4242,
            'country': 'US',
            'process_path': r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            'protocol_number': 6,
            'remote_port': 443,
            'block': <String, dynamic>{
              'app': r'C:\Program Files\Google\Chrome\Application\chrome.exe',
              'port': 443,
              'protocol': 6,
              'note': 'chrome-exe',
            },
          },
          // A UDP row: Windows keeps no peer for it, so there is no exact filter
          // to write and the engine sends no spec.
          <String, dynamic>{
            'local_address': '0.0.0.0:5353',
            'remote_address': '*:*',
            'protocol': 'UDP',
            'state': '-',
            'process_name': 'svchost.exe',
            'process_id': 5000,
            'country': '',
            'process_path': r'C:\Windows\System32\svchost.exe',
            'protocol_number': 17,
            'remote_port': 0,
          },
        ];
      case 'fw.wfp.block':
        if (refuse) {
          throw EngineException(
              'the Base Filtering Engine refused this process: needs an administrator');
        }
        return <String, dynamic>{'layers': 2};
    }
    return <String, dynamic>{};
  }
}

Widget _harness(EngineIpc ipc) => ProviderScope(
      overrides: [engineIpcProvider.overrideWithValue(ipc)],
      child: const MaterialApp(home: Scaffold(body: NetworkMonitorScreen())),
    );

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('a row with a peer port sends the spec the engine built',
      (tester) async {
    final ipc = _FakeIpc();
    await tester.pumpWidget(_harness(ipc));
    await tester.pumpAndSettle();

    // The snapshot is taken when the screen opens, not only when Refresh is
    // pressed.
    expect(ipc.requests, contains('net.connections'));

    // Only the blockable row has a button: the UDP row shows the reason it has
    // none instead of one that fails.
    expect(find.byType(IconButton), findsOneWidget);
    expect(find.textContaining('svchost.exe (5000)'), findsOneWidget);

    await tester.tap(find.byType(IconButton));
    await tester.pumpAndSettle();
    expect(find.textContaining('chrome.exe'), findsWidgets,
        reason: 'the confirmation names the program it is about to block');
    expect(find.textContaining('443'), findsWidgets);

    await tester.tap(find.byType(FilledButton));
    await tester.pumpAndSettle();

    expect(ipc.calls.length, 1);
    final call = ipc.calls.single;
    expect(call['method'], 'fw.wfp.block');
    expect(
      call['params'],
      <String, dynamic>{
        'app': r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        'port': 443,
        'protocol': 6,
        'note': 'chrome-exe',
      },
      reason: 'the UI forwards the engine spec untouched',
    );

    // And the refusal is reported, not swallowed: unelevated, this is the
    // answer the machine gives.
    expect(find.textContaining('needs an administrator'), findsOneWidget);
  });

  testWidgets('cancelling the confirmation writes nothing', (tester) async {
    final ipc = _FakeIpc();
    await tester.pumpWidget(_harness(ipc));
    await tester.pumpAndSettle();

    await tester.tap(find.byType(IconButton));
    await tester.pumpAndSettle();
    await tester.tap(find.descendant(
      of: find.byType(AlertDialog),
      matching: find.byType(TextButton),
    ));
    await tester.pumpAndSettle();

    expect(ipc.requests, isNot(contains('fw.wfp.block')),
        reason: 'a persistent filter is written only after the user says yes');
  });
}
