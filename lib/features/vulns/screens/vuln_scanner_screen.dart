import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/models/network_models.dart';

final vulnProvider =
    NotifierProvider<VulnNotifier, VulnState>(VulnNotifier.new);

/// Live state of the vulnerability scan: it is a job (NVD rate-limits it to
/// minutes), so the screen shows progress and can cancel instead of sitting on
/// a spinner it cannot stop.
class VulnState {
  final List<SoftwareVulns> results;
  final String? jobId;
  final String? jobState;
  final int pct;
  final int checked;
  final int total;
  final int cveCount;
  final String? current;
  final String? error;

  const VulnState({
    this.results = const <SoftwareVulns>[],
    this.jobId,
    this.jobState,
    this.pct = 0,
    this.checked = 0,
    this.total = 0,
    this.cveCount = 0,
    this.current,
    this.error,
  });

  /// A job is in flight while its state is not terminal.
  bool get scanning =>
      jobState == 'running' || jobState == 'queued' || jobState == 'interrupted';

  bool get cancelled => jobState == 'cancelled';
  bool get failed => jobState == 'failed';
}

class VulnNotifier extends Notifier<VulnState> {
  StreamSubscription<Map<String, dynamic>>? _progressSub;
  StreamSubscription<Map<String, dynamic>>? _eventSub;

  @override
  VulnState build() {
    final ipc = ref.read(engineIpcProvider);
    // Progress arrives as an engine push; the screen never polls.
    _progressSub = ipc.progressStream.listen(_onProgress);
    _eventSub = ipc.eventStream.listen(_onEvent);
    ref.onDispose(() {
      _progressSub?.cancel();
      _eventSub?.cancel();
    });
    return const VulnState();
  }

  /// Re-attaches to a scan that is already running (engine restart, or a job
  /// the service kept alive while this screen was closed).
  Future<void> attachRunningJob() async {
    try {
      final jobs =
          await ref.read(engineIpcProvider).request('job.list', {'limit': 10});
      final running = (jobs as List).cast<Map<String, dynamic>>().firstWhere(
            (j) =>
                j['kind'] == 'vuln_scan' &&
                const {'running', 'queued', 'interrupted'}
                    .contains(j['state'] as String?),
            orElse: () => const {},
          );
      if (running.isEmpty) return;
      state = VulnState(
        results: state.results,
        jobId: running['job_id'] as String?,
        jobState: running['state'] as String?,
        total: (running['total'] as num?)?.toInt() ?? 0,
        checked: (running['processed'] as num?)?.toInt() ?? 0,
        cveCount: (running['findings_count'] as num?)?.toInt() ?? 0,
      );
    } catch (_) {
      // No engine yet — the screen still works, it just has nothing to attach.
    }
  }

  Future<void> scan({int maxApps = 10}) async {
    state = VulnState(results: state.results, jobState: 'running');
    try {
      final res = await ref
          .read(engineIpcProvider)
          .request('vuln.scan.start', {'max_apps': maxApps});
      state = VulnState(
        results: state.results,
        jobId: (res as Map)['job_id'] as String?,
        jobState: 'running',
      );
    } catch (e) {
      state = VulnState(results: state.results, error: e.toString());
    }
  }

  void _onProgress(Map<String, dynamic> p) {
    if (p['job_id'] != state.jobId) return;
    final detail = p['detail'] as String?;
    final total = (p['total'] as num?)?.toInt() ?? state.total;
    state = VulnState(
      results: state.results,
      jobId: state.jobId,
      jobState: p['state'] as String? ?? state.jobState,
      pct: (p['pct'] as num?)?.toInt() ?? state.pct,
      checked: (p['scanned'] as num?)?.toInt() ?? state.checked,
      total: total,
      cveCount: (p['findings'] as num?)?.toInt() ?? state.cveCount,
      // The phase labels the engine sends at the start and the end are not
      // application names, so only keep one once the target list exists.
      current: total > 0 ? detail : null,
    );
  }

  void _onEvent(Map<String, dynamic> e) {
    if (e['type'] != 'job_finished') return;
    final data = (e['data'] as Map?)?.cast<String, dynamic>() ?? {};
    if (data['job_id'] != state.jobId) return;
    _loadCompletedJob(data['job_id'] as String);
  }

  /// Pulls the persisted job: the per-application findings were written as the
  /// scan went, so a cancelled job still shows everything it checked.
  Future<void> _loadCompletedJob(String jobId) async {
    try {
      final res = await ref
          .read(engineIpcProvider)
          .request('job.get', {'job_id': jobId});
      final map = (res as Map).cast<String, dynamic>();
      final job = (map['job'] as Map).cast<String, dynamic>();
      final findings = (map['findings'] as List? ?? [])
          .map((f) => SoftwareVulns.fromJson((f as Map).cast<String, dynamic>()))
          .toList();
      state = VulnState(
        results: findings,
        jobId: jobId,
        jobState: job['state'] as String?,
        pct: 100,
        total: (job['total'] as num?)?.toInt() ?? 0,
        checked: (job['processed'] as num?)?.toInt() ?? 0,
        cveCount: findings.fold<int>(
            0, (sum, item) => sum + item.vulnerabilities.length),
        current: null,
      );
    } catch (e) {
      state = VulnState(
        results: state.results,
        jobId: state.jobId,
        jobState: state.jobState,
        error: 'cannot load job $jobId: $e',
      );
    }
  }

  Future<void> stop() async {
    final id = state.jobId;
    if (id == null) return;
    try {
      await ref.read(engineIpcProvider).request('job.cancel', {'job_id': id});
    } catch (_) {
      // The job may have finished between the tap and the request.
    }
  }
}

Color cvssColor(double score) {
  if (score >= 9) return AppColors.red;
  if (score >= 7) return AppColors.orange;
  if (score >= 4) return const Color(0xFFEAB308);
  return AppColors.muted;
}

class VulnScannerScreen extends ConsumerStatefulWidget {
  const VulnScannerScreen({super.key});

  @override
  ConsumerState<VulnScannerScreen> createState() => _VulnScannerScreenState();
}

class _VulnScannerScreenState extends ConsumerState<VulnScannerScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // A scan may already be running (engine restart, or the service resuming
      // a job) — show its live progress instead of an idle screen.
      ref.read(vulnProvider.notifier).attachRunningJob();
    });
  }

  @override
  Widget build(BuildContext context) {
    final st = ref.watch(vulnProvider);

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(children: [
            Text(context.tr('nav.vulns'),
                style: TextStyle(
                    color: AppColors.text,
                    fontSize: 16,
                    fontWeight: FontWeight.w800)),
            const Spacer(),
            FilledButton.icon(
              onPressed: st.scanning
                  ? null
                  : () => ref.read(vulnProvider.notifier).scan(),
              icon: const Icon(Icons.radar, size: 18),
              label: Text(context.tr('vulns.scan')),
            ),
            if (st.scanning) ...[
              const SizedBox(width: 8),
              OutlinedButton.icon(
                onPressed: () => ref.read(vulnProvider.notifier).stop(),
                icon: const Icon(Icons.stop, size: 18),
                label: Text(context.tr('vulns.cancel')),
              ),
            ],
          ]),
        ),
        Padding(
          padding: EdgeInsets.symmetric(horizontal: 16),
          child: Align(
            alignment: AlignmentDirectional.centerStart,
            child: Text(
              context.tr('vulns.hint'),
              style: TextStyle(color: AppColors.muted, fontSize: 11),
            ),
          ),
        ),
        if (st.error != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 10, 16, 0),
            child: Align(
              alignment: AlignmentDirectional.centerStart,
              child: Text(st.error!,
                  style: TextStyle(color: AppColors.orange, fontSize: 12)),
            ),
          ),
        if (st.scanning) _VulnProgress(st: st),
        if (st.cancelled)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 10, 16, 0),
            child: Align(
              alignment: AlignmentDirectional.centerStart,
              child: Text(context.tr('vulns.cancelled'),
                  style: TextStyle(color: AppColors.orange, fontSize: 12)),
            ),
          ),
        Expanded(
          child: st.scanning && st.results.isEmpty
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      CircularProgressIndicator(),
                      SizedBox(height: 12),
                      Text(context.tr('vulns.loading'),
                          style: TextStyle(color: AppColors.muted)),
                    ],
                  ),
                )
              : ListView(
                  padding: const EdgeInsets.all(16),
                  children: [
                    for (final item in st.results) _SoftwareCard(item: item),
                  ],
                ),
        ),
      ],
    );
  }
}

/// Live job progress, driven by engine `progress` notifications (no polling).
class _VulnProgress extends StatelessWidget {
  const _VulnProgress({required this.st});
  final VulnState st;

  @override
  Widget build(BuildContext context) {
    final pct = st.pct.clamp(0, 100);
    // Built here, not inline: the copy goes through context.tr (and the i18n
    // lint requires any literal inside Text(...) to be interpolation only).
    final queue = st.total > 0
        ? context
            .tr('vulns.progress')
            .replaceAll('{done}', '${st.checked}')
            .replaceAll('{total}', '${st.total}')
        : context.tr('vulns.loading');
    final cves = context
        .tr('vulns.cvesSoFar')
        .replaceAll('{count}', '${st.cveCount}');
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 12, 16, 0),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.cyan.withValues(alpha: 0.35)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Icon(Icons.radar, size: 16, color: AppColors.cyan),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                st.current != null
                    ? context
                        .tr('vulns.current')
                        .replaceAll('{app}', st.current!)
                    : context.tr('vulns.loading'),
                style: TextStyle(color: AppColors.text, fontSize: 12.5),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            const SizedBox(width: 8),
            Text('$pct%',
                style: AppTheme.mono(size: 12, color: AppColors.cyan)),
          ]),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: st.total > 0 ? pct / 100 : null,
              minHeight: 6,
              backgroundColor: AppColors.background,
              valueColor: AlwaysStoppedAnimation(AppColors.cyan),
            ),
          ),
          const SizedBox(height: 8),
          Text(
            '$queue · $cves',
            style: AppTheme.mono(size: 10, color: AppColors.muted),
          ),
        ],
      ),
    );
  }
}

class _SoftwareCard extends StatelessWidget {
  const _SoftwareCard({required this.item});
  final SoftwareVulns item;

  @override
  Widget build(BuildContext context) {
    final vulns = item.vulnerabilities;
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.all(12),
            child: Row(children: [
              Text(item.software,
                  style: TextStyle(
                      color: AppColors.text,
                      fontWeight: FontWeight.w700,
                      fontSize: 14)),
              if (item.version.isNotEmpty) ...[
                const SizedBox(width: 8),
                Text(item.version,
                    style: AppTheme.mono(size: 11, color: AppColors.cyan)),
              ],
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(999),
                  border: Border.all(color: AppColors.border),
                ),
                child: Text(
                    item.fromCache
                        ? context.tr('vulns.cache')
                        : context.tr('vulns.live'),
                    style: AppTheme.mono(
                        size: 9,
                        color: item.fromCache
                            ? AppColors.muted
                            : AppColors.green)),
              ),
              const SizedBox(width: 8),
              Text(
                  context
                      .tr('vulns.count')
                      .replaceAll('{count}', '${vulns.length}'),
                  style: AppTheme.mono(size: 11, color: AppColors.muted)),
            ]),
          ),
          for (final v in vulns.take(5))
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                  border: Border(top: BorderSide(color: AppColors.border))),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    width: 4,
                    height: 30,
                    decoration: BoxDecoration(
                        color: cvssColor(v.cvss),
                        borderRadius: BorderRadius.circular(2)),
                  ),
                  const SizedBox(width: 10),
                  SizedBox(
                    width: 110,
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(v.cveId,
                              style: AppTheme.mono(
                                  size: 11, color: AppColors.text)),
                          Text(
                              context.tr('vulns.cvss').replaceAll(
                                  '{score}', v.cvss.toStringAsFixed(1)),
                              style: AppTheme.mono(
                                  size: 10, color: cvssColor(v.cvss))),
                        ]),
                  ),
                  Expanded(
                    child: Text(v.description,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                            color: AppColors.muted, fontSize: 11.5)),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}
