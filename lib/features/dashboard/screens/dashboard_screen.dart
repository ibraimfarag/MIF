import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/models/audit_models.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/providers/providers.dart';

class DashboardScreen extends ConsumerStatefulWidget {
  const DashboardScreen({super.key});

  @override
  ConsumerState<DashboardScreen> createState() => _DashboardScreenState();
}

/// Live L1–L5 health fetched from the engine's real subsystem state.
final layersProvider =
    NotifierProvider<LayersNotifier, AsyncValue<Map<String, double>>>(
        LayersNotifier.new);

class LayersNotifier extends Notifier<AsyncValue<Map<String, double>>> {
  @override
  AsyncValue<Map<String, double>> build() =>
      const AsyncValue.data(<String, double>{});

  Future<void> refresh() async {
    try {
      final ipc = ref.read(engineIpcProvider);
      final guard = await ipc.request('guard.status');
      final ids = await ipc.request('ids.status');
      final incidents = await ipc.request('incident.list', {'limit': 10});
      final guardRunning = (guard as Map)['running'] as bool? ?? false;
      final blockedCount =
          ((ids as Map)['blocked_domains'] as List? ?? []).length;
      final incidentCount = (incidents as List? ?? []).length;
      state = AsyncValue.data({
        // L1: audit-derived (vulnerable+warning findings).
        'L1': -1, // filled by caller from report
        // L2: live once the DNS blocklist has entries.
        'L2': blockedCount > 0 ? 1.0 : 0.0,
        // L3: live when the guard loop is running.
        'L3': guardRunning ? 1.0 : 0.0,
        // L4: scanner is built-in — healthy whenever the engine is up.
        'L4': 1.0,
        // L5: correlator has handled at least one incident, else idle-but-ready.
        'L5': incidentCount > 0 ? 1.0 : 0.35,
      });
    } catch (_, st) {
      state = AsyncValue.error('layer state unavailable', st);
    }
  }
}

class _DashboardScreenState extends ConsumerState<DashboardScreen>
    with SingleTickerProviderStateMixin {
  late final AnimationController _gauge =
      AnimationController(vsync: this, duration: const Duration(milliseconds: 900))
        ..forward();

  @override
  void initState() {
    super.initState();
    final audit = ref.read(auditProvider);
    if (audit.report == null && !audit.loading) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        ref.read(auditProvider.notifier).runAudit();
      });
    }
    // Safety net: if the first audit never lands (slow engine spawn, raced
    // request), retry after 6 s instead of spinning forever.
    _retryTimer = Timer.periodic(const Duration(seconds: 6), (t) {
      final st = ref.read(auditProvider);
      if (st.report != null) {
        t.cancel();
        ref.read(layersProvider.notifier).refresh();
        return;
      }
      if (!st.loading && t.tick > 1) {
        ref.read(auditProvider.notifier).runAudit();
      }
    });
    // Retry once the engine reconnects (covers cold start races).
    _engineSub = ref.listenManual(engineStateProvider, (prev, next) {
      if (next.value == EngineState.running &&
          ref.read(auditProvider).report == null) {
        ref.read(auditProvider.notifier).runAudit();
      }
    });
    // Refresh the L2–L5 live state the moment a report lands, so the layer
    // cards never sit on "idle" until the safety-net timer fires.
    _auditSub = ref.listenManual(auditProvider, (prev, next) {
      if (next.report != null) {
        ref.read(layersProvider.notifier).refresh();
      }
    });
  }

  ProviderSubscription? _engineSub;
  ProviderSubscription? _auditSub;
  Timer? _retryTimer;

  @override
  void dispose() {
    _retryTimer?.cancel();
    _engineSub?.close();
    _auditSub?.close();
    _gauge.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(auditProvider);
    final report = state.report;

    return RefreshIndicator(
      onRefresh: () => ref.read(auditProvider.notifier).runAudit(),
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          if (state.loading && report == null)
            _LoadingCard(label: context.tr('audit.loading'))
          else if (state.error != null && report == null)
            _ErrorCard(
                message: state.error!,
                onRetry: () => ref.read(auditProvider.notifier).runAudit())
          else if (report != null) ...[
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _ScoreCard(score: report.score, gauge: _gauge),
                const SizedBox(width: 16),
                Expanded(child: _WhatNowCard(top: report.topAction)),
              ],
            ),
            const SizedBox(height: 16),
            _FindingsSummary(report: report),
            const SizedBox(height: 16),
            _LayerHealth(report: report),
          ],
        ],
      ),
    );
  }
}

class _ScoreCard extends StatelessWidget {
  const _ScoreCard({required this.score, required this.gauge});
  final int score;
  final AnimationController gauge;

  @override
  Widget build(BuildContext context) {
    final color = AppColors.scoreColor(score);
    return Container(
      width: 220,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        children: [
          Text(context.tr('score.title'),
              style: TextStyle(color: AppColors.muted, fontSize: 13)),
          const SizedBox(height: 12),
          SizedBox(
            width: 150,
            height: 150,
            child: AnimatedBuilder(
              animation: gauge,
              builder: (_, _) => CustomPaint(
                painter: _GaugePainter(
                  progress: CurvedAnimation(
                          parent: gauge, curve: Curves.easeOutCubic)
                      .value,
                  score: score,
                  color: color,
                ),
                child: Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text('${(score * gauge.value).round()}',
                          style: AppTheme.mono(size: 40, color: color)),
                      // Numeric scores stay LTR even in an RTL layout.
                      Directionality(
                        textDirection: TextDirection.ltr,
                        child: Text('/100',
                            style:
                                AppTheme.mono(size: 12, color: AppColors.muted)),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _GaugePainter extends CustomPainter {
  _GaugePainter(
      {required this.progress, required this.score, required this.color});
  final double progress;
  final int score;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2 - 10;
    const startAngle = math.pi * 0.75;
    final sweep = math.pi * 1.5;

    final track = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 10
      ..strokeCap = StrokeCap.round
      ..color = AppColors.border;
    canvas.drawArc(Rect.fromCircle(center: center, radius: radius), startAngle,
        sweep, false, track);

    final value = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 10
      ..strokeCap = StrokeCap.round
      ..color = color;
    canvas.drawArc(Rect.fromCircle(center: center, radius: radius), startAngle,
        sweep * progress * (score / 100), false, value);
  }

  @override
  bool shouldRepaint(_GaugePainter old) =>
      old.progress != progress || old.score != score;
}

class _WhatNowCard extends StatelessWidget {
  const _WhatNowCard({required this.top});
  final AuditFinding? top;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Icon(Icons.auto_awesome, color: AppColors.cyan, size: 18),
            const SizedBox(width: 8),
            Text(context.tr('score.whatNow'),
                style: TextStyle(
                    color: AppColors.cyan,
                    fontWeight: FontWeight.w700,
                    fontSize: 15)),
          ]),
          const SizedBox(height: 12),
          if (top == null)
            Text('✅ ${context.tr('status.secure')} — ${context.tr('app.tagline')}',
                style: TextStyle(color: AppColors.green))
          else ...[
            Text(context.tr('score.doFirst'),
                style: TextStyle(color: AppColors.muted, fontSize: 13)),
            const SizedBox(height: 8),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  margin: const EdgeInsets.only(top: 2),
                  width: 4,
                  height: 40,
                  decoration: BoxDecoration(
                      color: top!.severityColor,
                      borderRadius: BorderRadius.circular(2)),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('${top!.section} :: ${top!.item}',
                          style: TextStyle(
                              fontWeight: FontWeight.w700,
                              color: AppColors.text)),
                      const SizedBox(height: 4),
                      Text(top!.description,
                          style: TextStyle(
                              color: AppColors.muted, fontSize: 13)),
                    ],
                  ),
                ),
              ],
            ),
            if (top!.fixAvailable) ...[
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: () => context.go('/hardening'),
                icon: const Icon(Icons.build_circle_outlined, size: 18),
                label: Text(context.tr('common.fix')),
              ),
            ],
          ],
        ],
      ),
    );
  }
}

class _FindingsSummary extends StatelessWidget {
  const _FindingsSummary({required this.report});
  final AuditReport report;

  @override
  Widget build(BuildContext context) {
    final buckets = [
      ('common.vulnerable', 'Vulnerable', report.countByStatus('Vulnerable')),
      ('common.warning', 'Warning', report.countByStatus('Warning')),
      ('common.secure', 'Secure', report.countByStatus('Secure')),
      ('common.unknown', 'Unknown', report.countByStatus('Unknown')),
    ];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(context.tr('dashboard.summary'),
            style: TextStyle(
                color: AppColors.text,
                fontWeight: FontWeight.w700,
                fontSize: 16)),
        const SizedBox(height: 8),
        Row(
          children: [
            for (final (key, status, count) in buckets) ...[
              Expanded(
                child: _SummaryTile(
                  label: context.tr(key),
                  count: count,
                  color: statusColor(status),
                ),
              ),
              const SizedBox(width: 10),
            ],
          ],
        ),
      ],
    );
  }
}

Color statusColor(String status) => switch (status) {
      'Secure' => AppColors.green,
      'Warning' => AppColors.orange,
      'Vulnerable' => AppColors.red,
      _ => AppColors.muted,
    };

class _SummaryTile extends StatelessWidget {
  const _SummaryTile(
      {required this.label, required this.count, required this.color});
  final String label;
  final int count;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        children: [
          Text('$count', style: AppTheme.mono(size: 24, color: color)),
          const SizedBox(height: 4),
          Text(label,
              style: TextStyle(color: AppColors.muted, fontSize: 12)),
        ],
      ),
    );
  }
}

class _LayerHealth extends ConsumerWidget {
  const _LayerHealth({required this.report});
  final AuditReport report;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // L1 comes from the audit posture; L2–L5 come from the engine's live
    // subsystem state (`layersProvider` -> guard.status / ids.status /
    // incident.list). A missing value means "not reporting yet", never
    // "planned for a later phase".
    final live = ref.watch(layersProvider).value ?? const <String, double>{};
    final vulnerable = report.countByStatus('Vulnerable');
    final warning = report.countByStatus('Warning');
    final layers = [
      ('L1', context.tr('layer.l1'), vulnerable + warning > 0 ? 0.6 : 1.0),
      ('L2', context.tr('layer.l2'), live['L2'] ?? 0.0),
      ('L3', context.tr('layer.l3'), live['L3'] ?? 0.0),
      ('L4', context.tr('layer.l4'), live['L4'] ?? 0.0),
      ('L5', context.tr('layer.l5'), live['L5'] ?? 0.0),
    ];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(context.tr('dashboard.liveFeed'),
            style: TextStyle(
                color: AppColors.text,
                fontWeight: FontWeight.w700,
                fontSize: 16)),
        const SizedBox(height: 8),
        Row(
          children: [
            for (final (id, name, health) in layers) ...[
              Expanded(
                child: _LayerTile(id: id, name: name, health: health),
              ),
              const SizedBox(width: 10),
            ],
          ],
        ),
      ],
    );
  }
}

class _LayerTile extends StatelessWidget {
  const _LayerTile({required this.id, required this.name, required this.health});
  final String id;
  final String name;
  final double health;

  @override
  Widget build(BuildContext context) {
    final color = health >= 0.9
        ? AppColors.green
        : health > 0
            ? AppColors.orange
            : AppColors.muted;
    final status = health >= 1.0
        ? context.tr('layer.active')
        : health > 0
            ? context.tr('layer.partial')
            : context.tr('layer.idle');
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        children: [
          Text(id, style: AppTheme.mono(size: 16, color: color)),
          const SizedBox(height: 4),
          Text(name,
              style: TextStyle(color: AppColors.muted, fontSize: 11),
              textAlign: TextAlign.center,
              maxLines: 2),
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: health.clamp(0.0, 1.0),
              minHeight: 4,
              backgroundColor: AppColors.border,
              valueColor: AlwaysStoppedAnimation(color),
            ),
          ),
          const SizedBox(height: 6),
          Text(status,
              style: TextStyle(fontSize: 8.5, color: color)),
        ],
      ),
    );
  }
}

class _LoadingCard extends StatelessWidget {
  const _LoadingCard({required this.label});
  final String label;

  @override
  Widget build(BuildContext context) {
    // Skeleton cards: the dashboard shows structure immediately instead of a
    // bare spinner while the engine collects live data.
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(children: [
          _SkeletonBox(width: 220, height: 214, radius: 16),
          const SizedBox(width: 16),
          Expanded(child: _SkeletonBox(width: double.infinity, height: 214, radius: 16)),
        ]),
        const SizedBox(height: 16),
        Row(children: [
          for (var i = 0; i < 4; i++) ...[
            Expanded(child: _SkeletonBox(width: double.infinity, height: 76, radius: 12)),
            if (i < 3) const SizedBox(width: 10),
          ],
        ]),
        const SizedBox(height: 16),
        Row(children: [
          for (var i = 0; i < 5; i++) ...[
            Expanded(child: _SkeletonBox(width: double.infinity, height: 96, radius: 12)),
            if (i < 4) const SizedBox(width: 10),
          ],
        ]),
        const SizedBox(height: 16),
        Center(
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            SizedBox(width: 14, height: 14,
                child: CircularProgressIndicator(strokeWidth: 2)),
            const SizedBox(width: 8),
            Text(label, style: TextStyle(color: AppColors.muted, fontSize: 12)),
          ]),
        ),
      ],
    );
  }
}

class _SkeletonBox extends StatefulWidget {
  const _SkeletonBox(
      {required this.width, required this.height, required this.radius});
  final double width;
  final double height;
  final double radius;

  @override
  State<_SkeletonBox> createState() => _SkeletonBoxState();
}

class _SkeletonBoxState extends State<_SkeletonBox>
    with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(
      vsync: this, duration: const Duration(milliseconds: 1100))
    ..repeat(reverse: true);

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _c,
      builder: (_, _) => Container(
        width: widget.width,
        height: widget.height,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(widget.radius),
          border: Border.all(color: AppColors.border),
          color: Color.lerp(AppColors.surface, AppColors.border,
              0.25 + 0.25 * _c.value),
        ),
      ),
    );
  }
}

class _ErrorCard extends StatelessWidget {
  const _ErrorCard({required this.message, required this.onRetry});
  final String message;
  final VoidCallback onRetry;
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.red.withValues(alpha: 0.4)),
      ),
      child: Column(children: [
        Icon(Icons.error_outline, color: AppColors.red, size: 36),
        const SizedBox(height: 12),
        Text(message,
            style: TextStyle(color: AppColors.muted),
            textAlign: TextAlign.center),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: onRetry,
          icon: const Icon(Icons.refresh),
          label: Text(context.tr('common.refresh')),
        ),
      ]),
    );
  }
}
