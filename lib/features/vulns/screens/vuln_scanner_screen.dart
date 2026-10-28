import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/models/network_models.dart';

final vulnProvider =
    NotifierProvider<VulnNotifier, AsyncValue<List<SoftwareVulns>>>(
        VulnNotifier.new);

class VulnNotifier extends Notifier<AsyncValue<List<SoftwareVulns>>> {
  @override
  AsyncValue<List<SoftwareVulns>> build() =>
      const AsyncValue.data(<SoftwareVulns>[]);

  Future<void> scan({int maxApps = 10}) async {
    state = const AsyncValue.loading();
    try {
      final res = await ref
          .read(engineIpcProvider)
          .request('vuln.scan', {'max_apps': maxApps});
      state = AsyncValue.data((res as List)
          .map((v) => SoftwareVulns.fromJson(v as Map<String, dynamic>))
          .toList());
    } catch (e, st) {
      state = AsyncValue.error(e, st);
    }
  }
}

Color cvssColor(double score) {
  if (score >= 9) return AppColors.red;
  if (score >= 7) return AppColors.orange;
  if (score >= 4) return const Color(0xFFEAB308);
  return AppColors.muted;
}

class VulnScannerScreen extends ConsumerWidget {
  const VulnScannerScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final async = ref.watch(vulnProvider);

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
              onPressed: () => ref.read(vulnProvider.notifier).scan(),
              icon: const Icon(Icons.radar, size: 18),
              label: Text(context.tr('vulns.scan')),
            ),
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
        Expanded(
          child: async.when(
            data: (items) => ListView(
              padding: const EdgeInsets.all(16),
              children: [
                for (final item in items) _SoftwareCard(item: item),
              ],
            ),
            loading: () => Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  CircularProgressIndicator(),
                  SizedBox(height: 12),
                  Text(context.tr('vulns.loading'),
                      style: TextStyle(color: AppColors.muted)),
                ],
              ),
            ),
            error: (e, _) => Center(
              child: Text('$e', style: TextStyle(color: AppColors.red)),
            ),
          ),
        ),
      ],
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
