import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';

// ---------- models (engine JSON mirrors) ----------

class ScanFinding {
  final String path;
  final String sha256;
  final String reason;
  final String severity;
  ScanFinding({
    required this.path,
    required this.sha256,
    required this.reason,
    required this.severity,
  });
  factory ScanFinding.fromJson(Map<String, dynamic> j) => ScanFinding(
        path: j['path'] as String? ?? '',
        sha256: j['sha256'] as String? ?? '',
        reason: j['reason'] as String? ?? '',
        severity: j['severity'] as String? ?? 'high',
      );
}

class ScanReport {
  final String path;
  final int filesScanned;
  final int filesSkipped;
  final List<ScanFinding> findings;
  final int durationMs;
  final bool stopped;
  ScanReport({
    required this.path,
    required this.filesScanned,
    required this.filesSkipped,
    required this.findings,
    required this.durationMs,
    required this.stopped,
  });
  factory ScanReport.fromJson(Map<String, dynamic> j) => ScanReport(
        path: j['path'] as String? ?? '',
        filesScanned: (j['files_scanned'] as num?)?.toInt() ?? 0,
        filesSkipped: (j['files_skipped'] as num?)?.toInt() ?? 0,
        durationMs: (j['duration_ms'] as num?)?.toInt() ?? 0,
        stopped: j['stopped'] as bool? ?? false,
        findings: (j['findings'] as List? ?? [])
            .map((f) => ScanFinding.fromJson(f as Map<String, dynamic>))
            .toList(),
      );
}

class QuarantineEntry {
  final String blobId;
  final String originalPath;
  final String reason;
  final int size;
  final bool restored;
  QuarantineEntry({
    required this.blobId,
    required this.originalPath,
    required this.reason,
    required this.size,
    required this.restored,
  });
  factory QuarantineEntry.fromJson(Map<String, dynamic> j) => QuarantineEntry(
        blobId: j['blob_id'] as String? ?? '',
        originalPath: j['original_path'] as String? ?? '',
        reason: j['reason'] as String? ?? '',
        size: (j['size'] as num?)?.toInt() ?? 0,
        restored: j['restored'] as bool? ?? false,
      );
}

// ---------- state ----------

final scannerProvider =
    NotifierProvider<ScannerNotifier, ScannerState>(ScannerNotifier.new);

class ScannerState {
  final ScanReport? report;
  final bool scanning;
  final List<QuarantineEntry> quarantine;
  final String? error;
  const ScannerState(
      {this.report,
      this.scanning = false,
      this.quarantine = const [],
      this.error});
}

class ScannerNotifier extends Notifier<ScannerState> {
  @override
  ScannerState build() => const ScannerState();

  Future<void> scan(String path, bool quarantine) async {
    state = ScannerState(
        report: state.report, quarantine: state.quarantine, scanning: true);
    try {
      final res = await ref
          .read(engineIpcProvider)
          .request('scan.start', {'path': path, 'quarantine': quarantine});
      final report = ScanReport.fromJson(res as Map<String, dynamic>);
      state = ScannerState(report: report, quarantine: state.quarantine);
      await refreshQuarantine();
    } catch (e) {
      state = ScannerState(
          report: state.report,
          quarantine: state.quarantine,
          error: e.toString());
    }
  }

  Future<void> stop() async {
    await ref.read(engineIpcProvider).request('scan.stop');
  }

  Future<void> refreshQuarantine() async {
    try {
      final res = await ref.read(engineIpcProvider).request('quarantine.list');
      state = ScannerState(
        report: state.report,
        scanning: state.scanning,
        quarantine: (res as List)
            .map((e) => QuarantineEntry.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
    } catch (e) {
      state = ScannerState(report: state.report, error: e.toString());
    }
  }

  Future<void> restore(String blobId) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request('quarantine.restore', {'blob_id': blobId});
      await refreshQuarantine();
    } catch (e) {
      state = ScannerState(report: state.report, error: e.toString());
    }
  }

  Future<void> delete(String blobId) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request('quarantine.delete', {'blob_id': blobId});
      await refreshQuarantine();
    } catch (e) {
      state = ScannerState(report: state.report, error: e.toString());
    }
  }
}

// ---------- screen ----------

class ScannerScreen extends ConsumerStatefulWidget {
  const ScannerScreen({super.key});

  @override
  ConsumerState<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends ConsumerState<ScannerScreen> {
  final _pathController = TextEditingController();
  bool _quarantine = true;
  int _tab = 0;

  @override
  void initState() {
    super.initState();
    _pathController.text =
        '${Platform.environment['USERPROFILE'] ?? ''}\\Downloads';
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(scannerProvider.notifier).refreshQuarantine();
    });
  }

  @override
  void dispose() {
    _pathController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final st = ref.watch(scannerProvider);
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: SegmentedButton<int>(
            segments: [
              ButtonSegment(
                  value: 0,
                  label: Text(context.tr('nav.scanner')),
                  icon: const Icon(Icons.bug_report)),
              ButtonSegment(
                  value: 1,
                  label: const Text('Quarantine'),
                  icon: const Icon(Icons.lock_outline)),
            ],
            selected: {_tab},
            onSelectionChanged: (s) => setState(() => _tab = s.first),
          ),
        ),
        Expanded(
          child: _tab == 0
              ? _ScanTab(
                  st: st,
                  pathController: _pathController,
                  quarantine: _quarantine,
                  onQuarantineChanged: (v) =>
                      setState(() => _quarantine = v ?? true),
                )
              : _QuarantineTab(st: st),
        ),
      ],
    );
  }
}

class _ScanTab extends ConsumerWidget {
  const _ScanTab({
    required this.st,
    required this.pathController,
    required this.quarantine,
    required this.onQuarantineChanged,
  });
  final ScannerState st;
  final TextEditingController pathController;
  final bool quarantine;
  final ValueChanged<bool?> onQuarantineChanged;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Expanded(
              child: TextField(
                controller: pathController,
                style: AppTheme.mono(size: 12),
                decoration: const InputDecoration(
                    labelText: 'Folder or drive to scan',
                    hintText: r'C:\Users\...\Downloads'),
              ),
            ),
            const SizedBox(width: 8),
            Checkbox(
              value: quarantine,
              onChanged: onQuarantineChanged,
            ),
            Text('Auto-quarantine',
                style: TextStyle(fontSize: 12, color: AppColors.text)),
          ],
        ),
        const SizedBox(height: 8),
        Row(children: [
          FilledButton.icon(
            onPressed: st.scanning
                ? null
                : () => ref
                    .read(scannerProvider.notifier)
                    .scan(pathController.text.trim(), quarantine),
            icon: const Icon(Icons.play_arrow),
            label: const Text('Scan'),
          ),
          const SizedBox(width: 8),
          if (st.scanning)
            OutlinedButton.icon(
              onPressed: () => ref.read(scannerProvider.notifier).stop(),
              icon: const Icon(Icons.stop),
              label: const Text('Stop'),
            ),
          const SizedBox(width: 12),
          if (st.scanning)
            const SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2)),
        ]),
        if (st.error != null) ...[
          const SizedBox(height: 8),
          Text(st.error!,
              style: TextStyle(color: AppColors.orange, fontSize: 12)),
        ],
        const SizedBox(height: 16),
        if (st.report != null) ...[
          Text(
            '${st.report!.filesScanned} files scanned · ${st.report!.filesSkipped} skipped · ${st.report!.durationMs} ms${st.report!.stopped ? " · STOPPED" : ""}',
            style: AppTheme.mono(size: 12, color: AppColors.muted),
          ),
          const SizedBox(height: 8),
          if (st.report!.findings.isEmpty)
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppColors.green.withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(12),
                border:
                    Border.all(color: AppColors.green.withValues(alpha: 0.3)),
              ),
              child: Row(children: [
                Icon(Icons.check_circle, color: AppColors.green),
                SizedBox(width: 10),
                Expanded(
                  child: Text(
                      'No threats found — the triaged queue came back clean.',
                      style: TextStyle(color: AppColors.text, fontSize: 13)),
                ),
              ]),
            ),
          for (final f in st.report!.findings) _FindingTile(finding: f),
        ] else
          Padding(
            padding: EdgeInsets.all(24),
            child: Text(
              'Pick a folder and run a scan. Files are triaged (location × extension × size × age) so the riskiest are checked first: IOC hash cache, then YARA rules.',
              style: TextStyle(color: AppColors.muted, fontSize: 12.5),
            ),
          ),
      ],
    );
  }
}

class _FindingTile extends StatelessWidget {
  const _FindingTile({required this.finding});
  final ScanFinding finding;

  @override
  Widget build(BuildContext context) {
    final color =
        finding.severity == 'critical' ? AppColors.red : AppColors.orange;
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Container(
                width: 4,
                height: 28,
                decoration: BoxDecoration(
                    color: color, borderRadius: BorderRadius.circular(2))),
            const SizedBox(width: 10),
            Expanded(
              child: Text(finding.path,
                  style: TextStyle(color: AppColors.text, fontSize: 12.5),
                  overflow: TextOverflow.ellipsis),
            ),
          ]),
          const SizedBox(height: 6),
          Row(children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(999),
                color: color.withValues(alpha: 0.12),
              ),
              child: Text(finding.reason,
                  style: TextStyle(color: color, fontSize: 10)),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Text(finding.sha256,
                  style: AppTheme.mono(size: 10, color: AppColors.muted),
                  overflow: TextOverflow.ellipsis),
            ),
          ]),
        ],
      ),
    );
  }
}

class _QuarantineTab extends ConsumerWidget {
  const _QuarantineTab({required this.st});
  final ScannerState st;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final items = st.quarantine;
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      children: [
        Row(children: [
          Text('Quarantine (${items.where((e) => !e.restored).length} active)',
              style: TextStyle(
                  color: AppColors.text, fontWeight: FontWeight.w700)),
          const Spacer(),
          OutlinedButton.icon(
            onPressed: () =>
                ref.read(scannerProvider.notifier).refreshQuarantine(),
            icon: const Icon(Icons.refresh, size: 16),
            label: Text(context.tr('common.refresh')),
          ),
        ]),
        const SizedBox(height: 8),
        if (items.isEmpty)
          Padding(
            padding: EdgeInsets.all(24),
            child: Text(
              'Quarantine is empty. Files detected by IOC hashes or YARA rules are AES-256-GCM encrypted here with a DPAPI-protected key.',
              style: TextStyle(color: AppColors.muted, fontSize: 12.5),
            ),
          ),
        for (final e in items)
          Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                  color: e.restored
                      ? AppColors.border
                      : AppColors.red.withValues(alpha: 0.4)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(children: [
                  Expanded(
                    child: Text(e.originalPath,
                        style: TextStyle(
                            color: AppColors.text, fontSize: 12),
                        overflow: TextOverflow.ellipsis),
                  ),
                  if (!e.restored) ...[
                    IconButton(
                      tooltip: 'Restore',
                      icon: Icon(Icons.undo,
                          size: 16, color: AppColors.green),
                      onPressed: () => ref
                          .read(scannerProvider.notifier)
                          .restore(e.blobId),
                    ),
                    IconButton(
                      tooltip: 'Delete forever',
                      icon: Icon(Icons.delete_forever,
                          size: 16, color: AppColors.red),
                      onPressed: () =>
                          ref.read(scannerProvider.notifier).delete(e.blobId),
                    ),
                  ] else
                    Text('restored',
                        style:
                            TextStyle(color: AppColors.muted, fontSize: 10)),
                ]),
                Text('${e.reason} · ${e.size} bytes · ${e.blobId.substring(0, 12)}…',
                    style: AppTheme.mono(size: 10, color: AppColors.muted)),
              ],
            ),
          ),
      ],
    );
  }
}
