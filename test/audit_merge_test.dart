import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/features/audit/screens/audit_screen.dart';
import 'package:mics_app/models/audit_models.dart';
import 'package:mics_app/providers/providers.dart';

import '../qa/ui/fake_engine.dart';
import '../qa/ui/harness.dart';

/// Stands in for the engine: records every RPC and answers `audit.run`.
class _FakeIpc extends EngineIpc {
  final requests = <Map<String, dynamic>>[];
  Map<String, dynamic> report = _report();
  bool refuseMerge = false;

  @override
  Future<dynamic> request(String method,
      [Map<String, dynamic>? params,
      Duration timeout = const Duration(seconds: 120)]) async {
    requests.add({'method': method, 'params': params});
    if (method != 'audit.run') return <String, dynamic>{};
    if (params?['merge'] == true && refuseMerge) {
      throw EngineException(
          'audit.run failed: no full audit to merge into — run the full audit '
          'first (a partial report is not a base)',
          code: -32000);
    }
    return report;
  }
}

Map<String, dynamic> _finding(String status) => <String, dynamic>{
      'id': 'rdp',
      'section': 'Remote Access',
      'item': 'rdp check',
      'status': status,
      'severity': 'Low',
      'description': 'RDP state',
      'fix_available': true,
    };

/// The shape the engine returns for a full audit and for a merged re-read.
Map<String, dynamic> _report({String rdpStatus = 'Vulnerable'}) =>
    <String, dynamic>{
      'score': rdpStatus == 'Secure' ? 79 : 76,
      'findings': [_finding(rdpStatus)],
      'startup_entries': <Map<String, dynamic>>[],
      'scheduled_tasks': <Map<String, dynamic>>[],
      'sections': ['defender', 'rdp', 'startup', 'scheduled_tasks'],
      'section_times': {
        'defender': 1762000000,
        'rdp': rdpStatus == 'Secure' ? 1762003600 : 1762000000,
        'startup': 1762000000,
        'scheduled_tasks': 1762000000,
      },
      'partial': false,
      'merged': rdpStatus == 'Secure',
      'refreshed': rdpStatus == 'Secure' ? ['rdp'] : <String>[],
    };

/// A merged report whose untouched section is visibly older than the re-read
/// one: `defender` was collected an hour before `rdp` was.
Map<String, dynamic> _mergedReport() => <String, dynamic>{
      'score': 79,
      'findings': [
        <String, dynamic>{
          'id': 'defender',
          'section': 'Defender',
          'item': 'real-time protection',
          'status': 'Vulnerable',
          'severity': 'Low',
          'description': 'Defender real-time protection is off',
          'fix_available': false,
        },
        _finding('Secure'),
      ],
      'startup_entries': <Map<String, dynamic>>[],
      'scheduled_tasks': <Map<String, dynamic>>[],
      'sections': ['defender', 'rdp', 'startup', 'scheduled_tasks'],
      'section_times': {
        'defender': 1762000000,
        'rdp': 1762003600,
        'startup': 1762000000,
        'scheduled_tasks': 1762000000,
      },
      'partial': false,
      'merged': true,
      'refreshed': ['rdp'],
    };

ProviderContainer _container(EngineIpc ipc) {
  final container =
      ProviderContainer(overrides: [engineIpcProvider.overrideWithValue(ipc)]);
  addTearDown(container.dispose);
  return container;
}

void main() {
  test('a fix re-reads one section and asks the engine to merge it', () async {
    final ipc = _FakeIpc()..report = _report(rdpStatus: 'Secure');
    final container = _container(ipc);

    await container.read(auditProvider.notifier).refreshAfterFix('rdp_off');

    expect(ipc.requests, hasLength(1), reason: 'one RPC, not a full sweep');
    expect(ipc.requests.single['method'], 'audit.run');
    expect(ipc.requests.single['params'], {'sections': ['rdp'], 'merge': true},
        reason: 'the caller must name the section and ask for a merge');
    final report = container.read(auditProvider).report;
    expect(report, isNotNull);
    expect(report!.score, 79,
        reason: 'the merged report carries the engine-computed score');
    expect(report.findings.single.status, 'Secure',
        reason: 'the refreshed finding replaces the stale one');
  });

  test('every hardening action maps to the audit section it changes', () {
    // Action ids from `engine/src/hardening/mod.rs::list_actions`, section ids
    // from `AUDIT_SECTIONS`. A rename on either side fails here instead of
    // silently turning a fix into an unknown-section error.
    expect(auditSectionForHardeningAction, {
      'pua_protection': 'defender',
      'defender_scan_quick': 'defender',
      'smbv1_off': 'smbv1',
      'rdp_off': 'rdp',
      'uac_on': 'uac',
    });
  });

  test('an action with no section mapping still refreshes the audit', () async {
    final ipc = _FakeIpc();
    final container = _container(ipc);

    await container.read(auditProvider.notifier).refreshAfterFix('unknown');

    expect(ipc.requests.single['params'], isNull,
        reason: 'no mapping means the full audit, not a guessed section');
  });

  test('a refused merge falls back to the full audit instead of an error',
      () async {
    final ipc = _FakeIpc()..refuseMerge = true;
    final container = _container(ipc);

    await container.read(auditProvider.notifier).refreshAfterFix('uac_on');

    expect(ipc.requests.map((r) => r['params']).toList(), [
      {'sections': ['uac'], 'merge': true},
      null,
    ], reason: 'the fallback is the plain full audit');
    final state = container.read(auditProvider);
    expect(state.error, isNull,
        reason: 'the user asked for a re-check, not for an error');
    expect(state.report, isNotNull);
  });

  test('a full audit still asks for everything', () async {
    final ipc = _FakeIpc();
    final container = _container(ipc);

    await container.read(auditProvider.notifier).runAudit();

    expect(ipc.requests.single['params'], isNull);
    expect(container.read(auditProvider).report, isNotNull);
  });

  test('the model knows which sections a merged report did not re-read', () {
    final merged = AuditReport.fromJson(_mergedReport());
    expect(merged.merged, isTrue);
    expect(merged.refreshed, ['rdp']);
    expect(merged.wasReRead('rdp'), isTrue,
        reason: 'the section the fix re-read is current');
    expect(merged.wasReRead('defender'), isFalse,
        reason: 'everything else is only as fresh as the last full audit');
    expect(merged.collectedAt('defender'),
        DateTime.fromMillisecondsSinceEpoch(1762000000 * 1000));
    expect(merged.collectedAt('nope'), isNull,
        reason: 'a section the engine did not stamp has no age, not an epoch');

    // A full audit re-read everything, so nothing is stale.
    final full = AuditReport.fromJson(_report());
    expect(full.merged, isFalse);
    expect(full.wasReRead('defender'), isTrue);
  });

  testWidgets('the audit screen shows the age of the sections it did not re-read',
      (tester) async {
    // The engine answers with a merged report: `rdp` was re-read, `defender`
    // was not, and the two inventory sections came from the same full audit.
    final engine = FakeEngine(fixtures: {'audit.run': _mergedReport()});
    final mounted = await openScreen(tester, const AuditScreen(), engine: engine);
    await mounted.container.read(auditProvider.notifier).runAudit();
    await settle(tester);

    final labels = find.textContaining('Not re-checked now');
    expect(labels, findsNWidgets(3),
        reason: 'the defender card plus the two inventory headers — and never '
            'the finding whose section was re-read');
    final texts = labels
        .evaluate()
        .map((e) => e.widget)
        .whereType<Text>()
        .map((t) => t.data ?? '')
        .toList();
    expect(texts, hasLength(3));
    expect(texts.every((t) => RegExp(r'\d{1,2}:\d{2}').hasMatch(t)), isTrue,
        reason: 'each line names the time the section was really read: $texts');
  });
}
