import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/theme/app_theme.dart';

import 'package:mics_app/models/audit_models.dart';
import 'package:mics_app/providers/providers.dart';

class AuditScreen extends ConsumerWidget {
  const AuditScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(auditProvider);
    final report = state.report;

    if (state.loading && report == null) {
      return _Centered(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
        const CircularProgressIndicator(),
        const SizedBox(height: 16),
        Text(context.tr('audit.loading'),
            style: const TextStyle(color: AppColors.muted)),
      ]));
    }

    if (state.error != null && report == null) {
      return _Centered(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
        const Icon(Icons.error_outline, color: AppColors.red, size: 40),
        const SizedBox(height: 12),
        Text(context.tr('audit.error'),
            style: const TextStyle(color: AppColors.red)),
        const SizedBox(height: 8),
        OutlinedButton(
            onPressed: () => ref.read(auditProvider.notifier).runAudit(),
            child: Text(context.tr('common.refresh'))),
      ]));
    }

    if (report == null) {
      // Designed empty state with a one-click action.
      return _Centered(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
        const Icon(Icons.fact_check_outlined,
            color: AppColors.muted, size: 48),
        const SizedBox(height: 12),
        Text(context.tr('audit.empty.title'),
            style: const TextStyle(color: AppColors.text, fontSize: 16)),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: () => ref.read(auditProvider.notifier).runAudit(),
          icon: const Icon(Icons.play_arrow),
          label: Text(context.tr('audit.empty.action')),
        ),
      ]));
    }

    return RefreshIndicator(
      onRefresh: () => ref.read(auditProvider.notifier).runAudit(),
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Row(children: [
            Text(context.tr('audit.title'),
                style: const TextStyle(
                    color: AppColors.text,
                    fontSize: 18,
                    fontWeight: FontWeight.w800)),
            const SizedBox(width: 8),
            Text('(${report.findings.length} ${context.tr('audit.findings')})',
                style: AppTheme.mono(size: 12, color: AppColors.muted)),
            const Spacer(),
            if (state.loading)
              const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2)),
            const SizedBox(width: 8),
            OutlinedButton.icon(
              onPressed: () => ref.read(auditProvider.notifier).runAudit(),
              icon: const Icon(Icons.refresh, size: 18),
              label: Text(context.tr('common.refresh')),
            ),
          ]),
          const SizedBox(height: 4),
          Text(context.tr('audit.subtitle'),
              style: const TextStyle(color: AppColors.muted, fontSize: 12)),
          const SizedBox(height: 16),
          for (final f in report.findings) _FindingCard(finding: f),
          const SizedBox(height: 16),
          _SectionHeader(title: context.tr('audit.startup')),
          for (final s in report.startupEntries)
            ListTile(
              dense: true,
              leading: const Icon(Icons.rocket_launch_outlined,
                  color: AppColors.muted, size: 18),
              title: Text(s.name,
                  style: const TextStyle(color: AppColors.text, fontSize: 13)),
              subtitle: Text(s.command,
                  style: AppTheme.mono(size: 10, color: AppColors.muted),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis),
              trailing: Text(s.location,
                  style:
                      AppTheme.mono(size: 10, color: AppColors.cyan)),
            ),
          const SizedBox(height: 16),
          _SectionHeader(title: context.tr('audit.tasks')),
          if (report.scheduledTasks.isEmpty)
            const Padding(
              padding: EdgeInsets.all(12),
              child: Text('—',
                  style: TextStyle(color: AppColors.muted)),
            ),
          for (final t in report.scheduledTasks)
            ListTile(
              dense: true,
              leading: const Icon(Icons.schedule,
                  color: AppColors.muted, size: 18),
              title: Text(t.name,
                  style: const TextStyle(color: AppColors.text, fontSize: 13)),
              subtitle: Text(t.path,
                  style: AppTheme.mono(size: 10, color: AppColors.muted)),
            ),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader({required this.title});
  final String title;
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8, top: 8),
      child: Text(title,
          style: const TextStyle(
              color: AppColors.cyan, fontWeight: FontWeight.w700)),
    );
  }
}

class _FindingCard extends StatelessWidget {
  const _FindingCard({required this.finding});
  final AuditFinding finding;

  @override
  Widget build(BuildContext context) {
    final color = finding.statusColor;
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
            color: finding.status.isInsecure
                ? color.withValues(alpha: 0.5)
                : AppColors.border),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 4,
            constraints: const BoxConstraints(minHeight: 44),
            decoration: BoxDecoration(
                color: finding.severityColor,
                borderRadius: BorderRadius.circular(2)),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(children: [
                  Flexible(
                    child: Text('${finding.section} :: ${finding.item}',
                        style: const TextStyle(
                            color: AppColors.text,
                            fontWeight: FontWeight.w700,
                            fontSize: 14)),
                  ),
                  const SizedBox(width: 8),
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(999),
                      border: Border.all(color: color.withValues(alpha: 0.6)),
                    ),
                    child: Text(
                        context.tr('common.${finding.status.toLowerCase()}'),
                        style: TextStyle(color: color, fontSize: 10)),
                  ),
                  const SizedBox(width: 6),
                  Text(context.tr('common.${finding.severity.toLowerCase()}'),
                      style: AppTheme.mono(
                          size: 10, color: finding.severityColor)),
                ]),
                const SizedBox(height: 6),
                Text(finding.description,
                    style: const TextStyle(
                        color: AppColors.muted, fontSize: 12.5)),
              ],
            ),
          ),
          if (finding.fixAvailable)
            Padding(
              padding: const EdgeInsetsDirectional.only(start: 8),
              child: OutlinedButton(
                onPressed: () {},
                style: OutlinedButton.styleFrom(
                    visualDensity: VisualDensity.compact),
                child: Text(context.tr('common.fix')),
              ),
            ),
        ],
      ),
    );
  }
}

class _Centered extends StatelessWidget {
  const _Centered({required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) =>
      Center(child: Padding(padding: const EdgeInsets.all(24), child: child));
}

extension on String {
  bool get isInsecure => this == 'Vulnerable' || this == 'Warning';
}
