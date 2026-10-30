import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/models/audit_models.dart';
import 'package:mics_app/providers/providers.dart';

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
      'partial': false,
      'merged': rdpStatus == 'Secure',
      'refreshed': rdpStatus == 'Secure' ? ['rdp'] : <String>[],
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
}
