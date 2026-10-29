import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/features/vulns/screens/vuln_scanner_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Stands in for the engine: records the RPCs the screen makes and lets the
/// test push the same `progress` / `event` notifications the pipe delivers.
class _FakeIpc extends EngineIpc {
  final progress = StreamController<Map<String, dynamic>>.broadcast();
  final events = StreamController<Map<String, dynamic>>.broadcast();
  final requests = <String>[];
  final pending = <Map<String, dynamic>>[];
  bool cancelCalled = false;

  @override
  Stream<Map<String, dynamic>> get progressStream => progress.stream;

  @override
  Stream<Map<String, dynamic>> get eventStream => events.stream;

  @override
  Future<dynamic> request(String method,
      [Map<String, dynamic>? params,
      Duration timeout = const Duration(seconds: 120)]) async {
    requests.add(method);
    pending.add({'method': method, 'params': params});
    switch (method) {
      case 'settings.get':
        return <String, dynamic>{};
      case 'job.list':
        return <Map<String, dynamic>>[];
      case 'vuln.scan.start':
        return <String, dynamic>{
          'job_id': 'vuln_scan-test',
          'state': 'running',
        };
      case 'job.cancel':
        cancelCalled = true;
        return <String, dynamic>{'cancelled': true};
      case 'job.get':
        return <String, dynamic>{
          'job': <String, dynamic>{
            'job_id': 'vuln_scan-test',
            'kind': 'vuln_scan',
            'state': 'done',
            'total': 1,
            'processed': 1,
          },
          'findings': <Map<String, dynamic>>[
            {
              'software': '7-Zip 25.01 (x64)',
              'version': '25.01',
              'from_cache': true,
              'vulnerabilities': [
                {
                  'cve_id': 'CVE-2025-0411',
                  'cvss': 8.8,
                  'description': 'Mark-of-the-Web bypass',
                  'published': '2025-01-22T00:00:00.000',
                  'known_exploited': true,
                  'kev_due': '2025-02-27',
                }
              ],
            }
          ],
        };
    }
    return <String, dynamic>{};
  }
}

Widget _harness(EngineIpc ipc) => ProviderScope(
      overrides: [engineIpcProvider.overrideWithValue(ipc)],
      child: const MaterialApp(
        home: Scaffold(body: VulnScannerScreen()),
      ),
    );

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('the vulnerability scan runs as a job with live progress',
      (tester) async {
    final ipc = _FakeIpc();
    await tester.pumpWidget(_harness(ipc));
    await tester.pump();

    // A scan may already be running: the screen asks the engine for jobs.
    expect(ipc.requests, contains('job.list'));
    expect(ipc.requests, isNot(contains('vuln.scan')),
        reason: 'the blocking RPC would freeze the UI for minutes');

    await tester.tap(find.byIcon(Icons.radar));
    await tester.pump();
    expect(ipc.requests, contains('vuln.scan.start'),
        reason: 'the UI must start a cancellable job, not a blocking call');
    expect(ipc.requests, isNot(contains('vuln.scan')));
    expect(find.byIcon(Icons.stop), findsOneWidget,
        reason: 'a running job must be cancellable from the screen');

    // Engine-pushed progress: percentage, queue position and current app.
    ipc.progress.add(<String, dynamic>{
      'job_id': 'vuln_scan-test',
      'state': 'running',
      'pct': 25,
      'detail': '7-Zip 25.01 (x64)',
      'scanned': 1,
      'skipped': 0,
      'total': 4,
      'findings': 2,
    });
    await tester.pump();
    expect(find.text('25%'), findsOneWidget);
    expect(find.textContaining('7-Zip 25.01 (x64)'), findsOneWidget);
    expect(find.byType(LinearProgressIndicator), findsOneWidget);

    await tester.tap(find.byIcon(Icons.stop));
    await tester.pump();
    expect(ipc.cancelCalled, isTrue, reason: 'Stop must cancel the job id');

    // The terminal event pulls the persisted findings and renders them.
    ipc.events.add(<String, dynamic>{
      'type': 'job_finished',
      'data': <String, dynamic>{
        'job_id': 'vuln_scan-test',
        'state': 'done',
        'findings': 1,
      },
    });
    await tester.pump();
    await tester.pump();
    expect(ipc.requests, contains('job.get'));
    expect(find.text('7-Zip 25.01 (x64)'), findsOneWidget);
    expect(find.text('CVE-2025-0411'), findsOneWidget);
    expect(find.byIcon(Icons.stop), findsNothing,
        reason: 'a finished job must not offer a cancel button');
  });

  testWidgets('progress for another job is ignored', (tester) async {
    final ipc = _FakeIpc();
    await tester.pumpWidget(_harness(ipc));
    await tester.pump();
    await tester.tap(find.byIcon(Icons.radar));
    await tester.pump();

    ipc.progress.add(<String, dynamic>{
      'job_id': 'some-other-job',
      'state': 'running',
      'pct': 90,
      'scanned': 9,
      'total': 10,
      'findings': 9,
    });
    await tester.pump();
    expect(find.text('90%'), findsNothing,
        reason: 'progress must be matched by job id, not shown blindly');
    expect(find.byIcon(Icons.stop), findsOneWidget);
  });
}