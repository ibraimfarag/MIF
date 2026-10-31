import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';

class GuardEvent {
  final String type;
  final String severity;
  final String ruleId;
  final String ruleName;
  final int pid;
  final String process;
  final String detail;
  final int at;
  GuardEvent({
    required this.type,
    required this.severity,
    required this.ruleId,
    required this.ruleName,
    required this.pid,
    required this.process,
    required this.detail,
    required this.at,
  });

  factory GuardEvent.fromJson(Map<String, dynamic> j) => GuardEvent(
        type: j['type'] as String? ?? '',
        severity: j['severity'] as String? ?? 'high',
        ruleId: j['rule_id'] as String? ?? '',
        ruleName: j['rule_name'] as String? ?? '',
        pid: (j['pid'] as num?)?.toInt() ?? 0,
        process: j['process'] as String? ?? '',
        detail: j['detail'] as String? ?? '',
        at: (j['at'] as num?)?.toInt() ?? 0,
      );

  DateTime get time =>
      DateTime.fromMillisecondsSinceEpoch(at * 1000, isUtc: true).toLocal();
}

class GuardRule {
  final String id;
  final String name;
  final String severity;
  final String action;
  GuardRule(
      {required this.id,
      required this.name,
      required this.severity,
      required this.action});
  factory GuardRule.fromJson(Map<String, dynamic> j) => GuardRule(
        id: j['id'] as String? ?? '',
        name: j['name'] as String? ?? '',
        severity: j['severity'] as String? ?? 'high',
        action: j['action'] as String? ?? 'alert',
      );
}

class GuardUiState {
  final bool running;
  final List<GuardRule> rules;
  final List<GuardEvent> events;
  final Map<String, bool> muteSuggested; // category -> suggested
  GuardUiState(
      {this.running = false,
      this.rules = const [],
      this.events = const [],
      this.muteSuggested = const {}});
}

final guardProvider =
    NotifierProvider<GuardNotifier, GuardUiState>(GuardNotifier.new);

class GuardNotifier extends Notifier<GuardUiState> {
  StreamSubscription? _eventsSub;

  @override
  GuardUiState build() {
    // Subscribe to pushed engine events once.
    _eventsSub ??= ref
        .read(engineIpcProvider)
        .eventStream
        .map((p) => GuardEvent.fromJson(p))
        .listen((ev) {
      state = GuardUiState(
          running: state.running,
          rules: state.rules,
          events: [ev, ...state.events].take(100).toList(),
          muteSuggested: state.muteSuggested);
    });
    ref.onDispose(() => _eventsSub?.cancel());
    return GuardUiState();
  }

  Future<void> refresh() async {
    try {
      final ipc = ref.read(engineIpcProvider);
      final st = await ipc.request('guard.status');
      final map = st as Map;
      state = GuardUiState(
        running: map['running'] as bool? ?? false,
        rules: (map['rules'] as List? ?? [])
            .map((r) => GuardRule.fromJson(r as Map<String, dynamic>))
            .toList(),
        events: state.events,
      );
    } catch (_) {}
  }

  /// Records a dismissal; surfaces the mute offer at 5 dismissals.
  Future<void> dismiss(GuardEvent ev) async {
    final category = '${ev.type}:${ev.ruleId}';
    state = GuardUiState(
        running: state.running,
        rules: state.rules,
        events: state.events,
        muteSuggested: state.muteSuggested);
    try {
      final res = await ref
          .read(engineIpcProvider)
          .request('guard.event.dismiss', {'category': category});
      final suggested = (res as Map)['mute_suggested'] as bool? ?? false;
      if (suggested) {
        state = GuardUiState(
          running: state.running,
          rules: state.rules,
          events: state.events,
          muteSuggested: {...state.muteSuggested, category: true},
        );
      }
    } catch (_) {}
  }

  Future<void> mute(String category) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request('noise.mute', {'category': category});
      state = GuardUiState(
        running: state.running,
        rules: state.rules,
        events: state.events,
        muteSuggested: {...state.muteSuggested, category: false},
      );
    } catch (_) {}
  }

  Future<void> toggle() async {
    final ipc = ref.read(engineIpcProvider);
    await ipc.request(state.running ? 'guard.stop' : 'guard.start');
    await refresh();
  }
}

class GuardScreen extends ConsumerStatefulWidget {
  const GuardScreen({super.key});

  @override
  ConsumerState<GuardScreen> createState() => _GuardScreenState();
}

class _GuardScreenState extends ConsumerState<GuardScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(guardProvider.notifier).refresh();
    });
  }

  @override
  Widget build(BuildContext context) {
    final st = ref.watch(guardProvider);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(children: [
          Icon(Icons.monitor_heart, color: AppColors.cyan),
          const SizedBox(width: 8),
          Text(context.tr('nav.guard'),
              style: TextStyle(
                  color: AppColors.text,
                  fontSize: 16,
                  fontWeight: FontWeight.w800)),
          const Spacer(),
          FilledButton.icon(
            onPressed: () => ref.read(guardProvider.notifier).toggle(),
            icon: Icon(st.running ? Icons.stop : Icons.play_arrow),
            label: Text(st.running ? 'Stop Guard' : 'Start Guard'),
            style: FilledButton.styleFrom(
              backgroundColor:
                  st.running ? AppColors.red : AppColors.green,
              foregroundColor: AppColors.background,
            ),
          ),
        ]),
        const SizedBox(height: 6),
        Text(
          st.running
              ? context.tr('guard.live')
              : context.tr('guard.stopped'),
          style: TextStyle(color: AppColors.muted, fontSize: 12),
        ),
        const SizedBox(height: 16),
        Text(
            context
                .tr('guard.rules')
                .replaceAll('{count}', '${st.rules.length}'),
            style: TextStyle(color: AppColors.cyan, fontWeight: FontWeight.w700)),
        const SizedBox(height: 8),
        for (final r in st.rules)
          Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border),
            ),
            child: Row(children: [
              Text(r.id, style: AppTheme.mono(size: 11, color: AppColors.cyan)),
              const SizedBox(width: 10),
              Expanded(
                child: Text(r.name,
                    style:
                        TextStyle(color: AppColors.text, fontSize: 12.5)),
              ),
              if (r.action == 'kill')
                Icon(Icons.gavel, size: 14, color: AppColors.red),
            ]),
          ),
        const SizedBox(height: 16),
        Text(
            context
                .tr('guard.events')
                .replaceAll('{count}', '${st.events.length}'),
            style: TextStyle(
                color: AppColors.cyan, fontWeight: FontWeight.w700)),
        const SizedBox(height: 8),
        if (st.events.isEmpty)
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: AppColors.border),
            ),
            child: Text(
              context.tr('guard.empty'),
              style: TextStyle(color: AppColors.muted, fontSize: 12.5),
            ),
          ),
        for (final e in st.events)
          _EventTile(
            ev: e,
            onDismiss: () => ref.read(guardProvider.notifier).dismiss(e),
          ),
        for (final entry in st.muteSuggested.entries)
          if (entry.value)
            Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: AppColors.orange.withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(8),
                border:
                    Border.all(color: AppColors.orange.withValues(alpha: 0.4)),
              ),
              child: Row(children: [
                Icon(Icons.notifications_off_outlined,
                    size: 15, color: AppColors.orange),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(context.tr('guard.muteOffer'),
                      style: TextStyle(
                          color: AppColors.text, fontSize: 12)),
                ),
                TextButton(
                  onPressed: () =>
                      ref.read(guardProvider.notifier).mute(entry.key),
                  child: Text(context.tr('guard.mute')),
                ),
              ]),
            ),
      ],
    );
  }
}

class _EventTile extends StatelessWidget {
  const _EventTile({required this.ev, required this.onDismiss});
  final GuardEvent ev;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final critical = ev.severity == 'critical';
    final color = critical ? AppColors.red : AppColors.orange;
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Icon(
                ev.type == 'canary_triggered'
                    ? Icons.egg
                    : Icons.warning_amber_rounded,
                size: 15,
                color: color),
            const SizedBox(width: 6),
            Text(ev.ruleName,
                style: TextStyle(
                    color: color,
                    fontWeight: FontWeight.w700,
                    fontSize: 12)),
            const Spacer(),
            Text(
                '${ev.time.hour.toString().padLeft(2, '0')}:${ev.time.minute.toString().padLeft(2, '0')}:${ev.time.second.toString().padLeft(2, '0')}',
                style: AppTheme.mono(size: 10, color: AppColors.muted)),
            IconButton(
              tooltip: context.tr('guard.dismiss'),
              visualDensity: VisualDensity.compact,
              icon: Icon(Icons.close, size: 13, color: AppColors.muted),
              onPressed: onDismiss,
            ),
          ]),
          const SizedBox(height: 4),
          Text(ev.detail,
              style: AppTheme.mono(size: 10.5, color: AppColors.muted),
              maxLines: 2,
              overflow: TextOverflow.ellipsis),
        ],
      ),
    );
  }
}
