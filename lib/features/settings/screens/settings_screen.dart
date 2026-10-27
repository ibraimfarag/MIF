import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final lang = ref.watch(localeProvider);
    final ipc = ref.watch(engineIpcProvider);

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(context.tr('settings.title'),
            style: const TextStyle(
                color: AppColors.text,
                fontSize: 18,
                fontWeight: FontWeight.w800)),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(context.tr('settings.language'),
                    style: const TextStyle(
                        color: AppColors.text,
                        fontWeight: FontWeight.w700)),
                const SizedBox(height: 12),
                SegmentedButton<AppLang>(
                  segments: [
                    ButtonSegment(
                        value: AppLang.ar,
                        label: Text(context.tr('lang.ar'))),
                    ButtonSegment(
                        value: AppLang.en,
                        label: Text(context.tr('lang.en'))),
                  ],
                  selected: {lang},
                  onSelectionChanged: (s) =>
                      ref.read(localeProvider.notifier).set(s.first),
                ),
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
                Text(context.tr('settings.enginePath'),
                    style: const TextStyle(
                        color: AppColors.text,
                        fontWeight: FontWeight.w700)),
                const SizedBox(height: 8),
                SelectableText(
                  ipc.resolveEnginePath(),
                  style: AppTheme.mono(size: 11, color: AppColors.cyan),
                ),
                const SizedBox(height: 8),
                Row(children: [
                  Icon(
                    switch (ipc.state) {
                      EngineState.running => Icons.check_circle,
                      EngineState.reconnecting => Icons.sync,
                      EngineState.engineMissing => Icons.error_outline,
                      EngineState.stopped => Icons.pause_circle_outline,
                    },
                    size: 14,
                    color: ipc.state == EngineState.running
                        ? AppColors.green
                        : AppColors.orange,
                  ),
                  const SizedBox(width: 6),
                  Text(
                    '${context.tr('state.engine')}: '
                    '${context.tr(switch (ipc.state) {
                      EngineState.running => 'engine.running',
                      EngineState.reconnecting => 'engine.reconnecting',
                      EngineState.engineMissing => 'engine.missing',
                      EngineState.stopped => 'engine.stopped',
                    })}',
                    style: const TextStyle(color: AppColors.muted, fontSize: 12),
                  ),
                ]),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
