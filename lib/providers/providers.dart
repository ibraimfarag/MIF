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

  Future<void> runAudit() async {
    if (state.loading) return;
    state = AuditState(loading: true, report: state.report);
    try {
      final result = await _ipc.request('audit.run');
      state = AuditState(report: AuditReport.fromJson(result));
    } catch (e) {
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
