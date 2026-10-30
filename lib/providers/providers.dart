import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/models/audit_models.dart';

/// Full audit state: not-run / loading / ready / error.
class AuditState {
  final AuditReport? report;
  final bool loading;
  final String? error;

  const AuditState({this.report, this.loading = false, this.error});
}

class AuditNotifier extends Notifier<AuditState> {
  @override
  AuditState build() {
    ref.watch(engineIpcProvider);
    return const AuditState();
  }

  EngineIpc get _ipc => ref.read(engineIpcProvider);

  /// Runs the audit.
  ///
  /// [sections] asks for a subset of the engine's checks (unknown names are
  /// refused by the engine, never ignored). [merge] re-reads those sections *on
  /// top of the last full audit*: the engine keeps the base, so the report stays
  /// complete and its score comparable. That is what a fix uses — one section in
  /// milliseconds instead of the whole sweep.
  Future<void> runAudit({List<String>? sections, bool merge = false}) =>
      _run(sections: sections, merge: merge, fallbackToFull: merge);

  /// Re-checks the audit section a hardening action changes, so the finding and
  /// the score stop claiming the machine is in its previous state. An action the
  /// engine has no section for falls back to the full audit.
  Future<void> refreshAfterFix(String actionId) {
    final section = auditSectionForHardeningAction[actionId];
    return runAudit(
        sections: section == null ? null : [section], merge: section != null);
  }

  Future<void> _run({
    List<String>? sections,
    bool merge = false,
    bool fallbackToFull = false,
  }) async {
    if (state.loading) return;
    state = AuditState(loading: true, report: state.report);
    final params = <String, dynamic>{
      'sections': ?sections,
      if (merge) 'merge': true,
    };
    try {
      final result = await _ipc.request(
          'audit.run', params.isEmpty ? null : params);
      state = AuditState(report: AuditReport.fromJson(result));
    } catch (e) {
      if (fallbackToFull) {
        // The engine refuses a merge with no full audit behind it (a partial
        // report is not a base). The caller asked for a re-check, so take the
        // full sweep rather than surfacing an error nobody can act on.
        state = AuditState(report: state.report);
        await _run();
        return;
      }
      state = AuditState(report: state.report, error: e.toString());
    }
  }
}

final auditProvider =
    NotifierProvider<AuditNotifier, AuditState>(AuditNotifier.new);

/// Engine connection state surfaced in the top bar.
final engineStateProvider = StreamProvider<EngineState>((ref) {
  final ipc = ref.watch(engineIpcProvider);
  // Kick off the first connection attempt eagerly.
  ipc.ensureRunning();
  return ipc.statusStream;
});
