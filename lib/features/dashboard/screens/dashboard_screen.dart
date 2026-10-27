import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/models/audit_models.dart';
import 'package:mics_app/providers/providers.dart';

class DashboardScreen extends ConsumerStatefulWidget {
  const DashboardScreen({super.key});

  @override
  ConsumerState<DashboardScreen> createState() => _DashboardScreenState();
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
  }

  @override
  void dispose() {
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
                      Text('/100',
                          style:
                              AppTheme.mono(size: 12, color: AppColors.muted)),
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

class _LayerHealth extends StatelessWidget {
  const _LayerHealth({required this.report});
  final AuditReport report;

  @override
  Widget build(BuildContext context) {
    // L1–L5 health derived from live data. Later phases fill L2–L5 with
    // their own engines; today the audit feeds the general posture.
    final vulnerable = report.countByStatus('Vulnerable');
    final warning = report.countByStatus('Warning');
    final layers = [
      ('L1', 'Network Gate', vulnerable + warning > 0 ? 0.6 : 1.0),
      ('L2', 'Attack Radar', null), // Phase 4+
      ('L3', 'Response', null), // Phase 6
      ('L4', 'File Engines', null), // Phase 5
      ('L5', 'Mind', null), // Phase 6
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
  const _LayerTile(
      {required this.id, required this.name, required this.health});
  final String id;
  final String name;
  final double? health;

  @override
  Widget build(BuildContext context) {
    final color = health == null
        ? AppColors.muted
        : health! >= 0.9
            ? AppColors.green
            : AppColors.orange;
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
              value: health,
              minHeight: 4,
              backgroundColor: AppColors.border,
              valueColor: AlwaysStoppedAnimation(color),
            ),
          ),
          if (health == null) ...[
            const SizedBox(height: 6),
            Text('…', style: AppTheme.mono(size: 10, color: AppColors.muted)),
          ],
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
    return Container(
      padding: const EdgeInsets.all(32),
      alignment: Alignment.center,
      child: Column(children: [
        const CircularProgressIndicator(),
        const SizedBox(height: 16),
        Text(label, style: TextStyle(color: AppColors.muted)),
      ]),
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
