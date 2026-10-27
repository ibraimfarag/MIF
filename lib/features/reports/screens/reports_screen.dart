import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';

final reportsProvider =
    NotifierProvider<ReportsNotifier, String?>(ReportsNotifier.new);

class ReportsNotifier extends Notifier<String?> {
  @override
  String? build() => null;

  Future<String?> exportMarkdown() async {
    try {
      final res = await ref.read(engineIpcProvider).request('report.export');
      return ((res as Map)['path'] as String?) ?? 'report.md';
    } catch (e) {
      return 'Export failed: $e';
    }
  }
}

class ReportsScreen extends ConsumerStatefulWidget {
  const ReportsScreen({super.key});

  @override
  ConsumerState<ReportsScreen> createState() => _ReportsScreenState();
}

class _ReportsScreenState extends ConsumerState<ReportsScreen> {
  bool _exporting = false;
  String? _lastPath;

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(context.tr('nav.reports'),
            style: const TextStyle(
                color: AppColors.text,
                fontSize: 16,
                fontWeight: FontWeight.w800)),
        const SizedBox(height: 6),
        const Text(
          'Export the live audit score, all findings, startup entries and incident kill-chains as a Markdown report.',
          style: TextStyle(color: AppColors.muted, fontSize: 12),
        ),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(children: [
                  Icon(Icons.description, color: AppColors.cyan),
                  SizedBox(width: 8),
                  Text('Markdown security report',
                      style: TextStyle(
                          color: AppColors.text,
                          fontWeight: FontWeight.w700)),
                ]),
                const SizedBox(height: 12),
                FilledButton.icon(
                  onPressed: _exporting
                      ? null
                      : () async {
                          setState(() => _exporting = true);
                          final path = await ref
                              .read(reportsProvider.notifier)
                              .exportMarkdown();
                          setState(() {
                            _exporting = false;
                            _lastPath = path;
                          });
                        },
                  icon: const Icon(Icons.file_download),
                  label: const Text('Export now'),
                ),
                if (_exporting)
                  const Padding(
                    padding: EdgeInsets.only(top: 12),
                    child: SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2)),
                  ),
                if (_lastPath != null) ...[
                  const SizedBox(height: 12),
                  SelectableText(_lastPath!,
                      style: AppTheme.mono(size: 11, color: AppColors.green)),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Where everything lives',
                      style: TextStyle(
                          color: AppColors.text, fontWeight: FontWeight.w700)),
                  const SizedBox(height: 8),
                  Text(
                    'Intel + quarantine + snapshots:  %PROGRAMDATA%\\MICS\\\n'
                    'Reports:  Documents\\MICS-Reports\\\n'
                    'Rules (YARA + guard):  rules\\ next to mics-engine.exe',
                    style: const TextStyle(
                        fontFamily: 'JetBrainsMono', fontSize: 11,
                        color: AppColors.muted, height: 1.6),
                  ),
                ]),
          ),
        ),
      ],
    );
  }
}
