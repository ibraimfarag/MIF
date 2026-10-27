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
    final currentThemeMode =
        ref.watch(settingsProvider).value?.themeMode ?? ThemeMode.dark;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(context.tr('settings.title'),
            style: TextStyle(
                color: AppColors.text,
                fontSize: 18,
                fontWeight: FontWeight.w800)),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Appearance',
                    style: TextStyle(
                        color: AppColors.text, fontWeight: FontWeight.w700)),
                const SizedBox(height: 12),
                SegmentedButton<ThemeMode>(
                  segments: [
                    ButtonSegment(
                        value: ThemeMode.dark,
                        icon: Icon(Icons.dark_mode, size: 16),
                        label: Text('Dark')),
                    ButtonSegment(
                        value: ThemeMode.light,
                        icon: Icon(Icons.light_mode, size: 16),
                        label: Text('Light')),
                    ButtonSegment(
                        value: ThemeMode.system,
                        icon: Icon(Icons.settings_suggest, size: 16),
                        label: Text('System')),
                  ],
                  selected: {currentThemeMode},
                  onSelectionChanged: (s) =>
                      ref.read(settingsProvider.notifier).setThemeMode(s.first),
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
                Text(context.tr('settings.language'),
                    style: TextStyle(
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
                      ref.read(settingsProvider.notifier).setLang(s.first),
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
                Text('Boot with Windows (engine 24/7)',
                    style: TextStyle(
                        color: AppColors.text, fontWeight: FontWeight.w700)),
                const SizedBox(height: 4),
                Text(
                    'Adds/removes an HKCU Run entry for mics-engine --service. Alerts keep working with the UI closed.',
                    style: TextStyle(color: AppColors.muted, fontSize: 11)),
                const SizedBox(height: 8),
                Row(children: [
                  FilledButton.icon(
                    onPressed: () async {
                      try {
                        await ref
                            .read(engineIpcProvider)
                            .request('service.install');
                        if (context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                  content: Text('Engine added to startup')));
                        }
                      } catch (_) {}
                    },
                    icon: const Icon(Icons.power, size: 16),
                    label: const Text('Enable'),
                  ),
                  const SizedBox(width: 8),
                  OutlinedButton.icon(
                    onPressed: () async {
                      try {
                        await ref
                            .read(engineIpcProvider)
                            .request('service.remove');
                        if (context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                  content: Text('Engine removed from startup')));
                        }
                      } catch (_) {}
                    },
                    icon: const Icon(Icons.power_off, size: 16),
                    label: const Text('Disable'),
                  ),
                ]),
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
                Text('MI CS Assistant (LM Studio)',
                    style: TextStyle(
                        color: AppColors.text, fontWeight: FontWeight.w700)),
                const SizedBox(height: 4),
                Text(
                  'Point the engine at your local LM Studio (OpenAI-compatible). Falls back to built-in explanation templates when offline. Env: MICS_LM_URL, MICS_LM_MODEL, MICS_VT_API_KEY, MICS_IOC_FEED_URL, MICS_UPDATE_MANIFEST_URL.',
                  style: TextStyle(color: AppColors.muted, fontSize: 11),
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
                    style: TextStyle(
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
                    style: TextStyle(color: AppColors.muted, fontSize: 12),
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
