import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/features/guard/screens/guard_screen.dart' show GuardEvent;

class Incident {
  final int incidentId;
  final String title;
  final String severity;
  final int openedAt;
  final List<GuardEvent> timeline;
  final bool closed;
  Incident({
    required this.incidentId,
    required this.title,
    required this.severity,
    required this.openedAt,
    required this.timeline,
    required this.closed,
  });

  factory Incident.fromJson(Map<String, dynamic> j) => Incident(
        incidentId: (j['incident_id'] as num?)?.toInt() ?? 0,
        title: j['title'] as String? ?? '',
        severity: j['severity'] as String? ?? 'high',
        openedAt: (j['opened_at'] as num?)?.toInt() ?? 0,
        closed: j['closed'] as bool? ?? false,
        timeline: (j['timeline'] as List? ?? [])
            .map((e) => GuardEvent.fromJson(e as Map<String, dynamic>))
            .toList(),
      );

  DateTime get time => DateTime.fromMillisecondsSinceEpoch(openedAt * 1000,
          isUtc: true)
      .toLocal();
}

final incidentsProvider =
    NotifierProvider<IncidentsNotifier, List<Incident>>(IncidentsNotifier.new);

class IncidentsNotifier extends Notifier<List<Incident>> {
  @override
  List<Incident> build() => const [];

  Future<void> refresh() async {
    try {
      final res =
          await ref.read(engineIpcProvider).request('incident.list', {'limit': 50});
      state = (res as List)
          .map((i) => Incident.fromJson(i as Map<String, dynamic>))
          .toList();
    } catch (_) {}
  }

  Future<void> close(int id) async {
    await ref.read(engineIpcProvider).request('incident.close', {'incident_id': id});
    await refresh();
  }
}

class IncidentsScreen extends ConsumerStatefulWidget {
  const IncidentsScreen({super.key});

  @override
  ConsumerState<IncidentsScreen> createState() => _IncidentsScreenState();
}

class _IncidentsScreenState extends ConsumerState<IncidentsScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(incidentsProvider.notifier).refresh();
    });
  }

  @override
  Widget build(BuildContext context) {
    final incidents = ref.watch(incidentsProvider);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(children: [
          Icon(Icons.timeline, color: AppColors.cyan),
          const SizedBox(width: 8),
          Text(context.tr('nav.incidents'),
              style: TextStyle(
                  color: AppColors.text,
                  fontSize: 16,
                  fontWeight: FontWeight.w800)),
          const Spacer(),
          OutlinedButton.icon(
            onPressed: () => ref.read(incidentsProvider.notifier).refresh(),
            icon: const Icon(Icons.refresh, size: 16),
            label: Text(context.tr('common.refresh')),
          ),
        ]),
        const SizedBox(height: 6),
        Text(
          context.tr('incidents.intro'),
          style: TextStyle(color: AppColors.muted, fontSize: 12),
        ),
        const SizedBox(height: 16),
        if (incidents.isEmpty)
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: AppColors.green.withValues(alpha: 0.05),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: AppColors.green.withValues(alpha: 0.3)),
            ),
            child: Row(children: [
              Icon(Icons.verified_user, color: AppColors.green),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                    context.tr('incidents.empty'),
                    style: TextStyle(color: AppColors.text, fontSize: 13)),
              ),
            ]),
          ),
        for (final inc in incidents) _IncidentCard(inc: inc),
      ],
    );
  }
}

class _IncidentCard extends ConsumerWidget {
  const _IncidentCard({required this.inc});
  final Incident inc;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final critical = inc.severity == 'critical';
    final color = inc.closed
        ? AppColors.muted
        : critical
            ? AppColors.red
            : AppColors.orange;
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Container(
              width: 4,
              height: 30,
              decoration: BoxDecoration(
                  color: color, borderRadius: BorderRadius.circular(2)),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(inc.title,
                  style: TextStyle(
                      color: AppColors.text,
                      fontWeight: FontWeight.w700,
                      fontSize: 13)),
            ),
            Text('#${inc.incidentId}',
                style: AppTheme.mono(size: 10, color: AppColors.muted)),
          ]),
          const SizedBox(height: 4),
          Text(
              '${inc.time} · '
              '${context.tr('incidents.summary').replaceAll('{count}', '${inc.timeline.length}').replaceAll('{severity}', inc.severity)}'
              '${inc.closed ? ' · ${context.tr('incidents.closed')}' : ''}',
              style: AppTheme.mono(size: 10, color: AppColors.muted)),
          const SizedBox(height: 8),
          for (final (i, ev) in inc.timeline.indexed)
            Padding(
              padding: EdgeInsetsDirectional.only(start: i * 12.0),
              child: Row(children: [
                Icon(Icons.chevron_right, size: 12, color: AppColors.muted),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                      '${ev.ruleId} · ${ev.process.isEmpty ? ev.ruleName : ev.process} · ${ev.detail}',
                      style: AppTheme.mono(size: 10, color: AppColors.muted),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis),
                ),
              ]),
            ),
          if (!inc.closed) ...[
            const SizedBox(height: 8),
            Align(
              alignment: AlignmentDirectional.centerEnd,
              child: TextButton(
                onPressed: () =>
                    ref.read(incidentsProvider.notifier).close(inc.incidentId),
                child: Text(context.tr('incidents.markHandled')),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
