import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';

/// Complete application settings (D-008).
///
/// Every control writes through `settings.set`, which the engine validates and
/// persists in `%PROGRAMDATA%\MICS\settings.json`. There is no local-only
/// preference: what you see here is exactly what the engine uses.
class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final async = ref.watch(settingsProvider);
    final ipc = ref.watch(engineIpcProvider);
    final notifier = ref.read(settingsProvider.notifier);

    return async.when(
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (e, _) => Center(
        child: Text('${context.tr('settings.loadFailed')}: $e',
            style: TextStyle(color: AppColors.orange)),
      ),
      data: (s) => ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(context.tr('settings.title'),
              style: TextStyle(
                  color: AppColors.text,
                  fontSize: 18,
                  fontWeight: FontWeight.w800)),
          const SizedBox(height: 4),
          Text(
            context.tr('settings.subtitle'),
            style: TextStyle(color: AppColors.muted, fontSize: 11.5),
          ),
          const SizedBox(height: 16),

          // ---------- appearance ----------
          _Section(
            icon: Icons.palette_outlined,
            title: context.tr('settings.appearance'),
            children: [
              SegmentedButton<ThemeMode>(
                segments: [
                  ButtonSegment(
                      value: ThemeMode.dark,
                      icon: const Icon(Icons.dark_mode, size: 16),
                      label: Text(context.tr('settings.theme.dark'))),
                  ButtonSegment(
                      value: ThemeMode.light,
                      icon: const Icon(Icons.light_mode, size: 16),
                      label: Text(context.tr('settings.theme.light'))),
                  ButtonSegment(
                      value: ThemeMode.system,
                      icon: const Icon(Icons.settings_suggest, size: 16),
                      label: Text(context.tr('settings.theme.system'))),
                ],
                selected: {s.themeMode},
                onSelectionChanged: (v) => notifier.setThemeMode(v.first),
              ),
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
                selected: {s.lang},
                onSelectionChanged: (v) => notifier.setLang(v.first),
              ),
            ],
          ),

          // ---------- protection ----------
          _Section(
            icon: Icons.shield_outlined,
            title: context.tr('settings.protection'),
            children: [
              _Switch(
                title: context.tr('settings.guardAutostart'),
                subtitle: context.tr('settings.guardAutostartHint'),
                value: s.guardAutostart,
                onChanged: notifier.setGuardAutostart,
              ),
              _Switch(
                title: context.tr('settings.autoResume'),
                subtitle: context.tr('settings.autoResumeHint'),
                value: s.autoResumeScans,
                onChanged: notifier.setAutoResumeScans,
              ),
              _Switch(
                title: context.tr('settings.autoQuarantine'),
                subtitle: context.tr('settings.autoQuarantineHint'),
                value: s.scanQuarantineDefault,
                onChanged: notifier.setScanQuarantineDefault,
              ),
              const SizedBox(height: 8),
              _TextSetting(
                label: context.tr('settings.canaryPaths'),
                hint: context.tr('settings.canaryPathsHint'),
                initial: s.canaryPaths.join('\n'),
                multiline: true,
                onSave: (value) => notifier.setCanaryPaths(value
                    .split('\n')
                    .map((e) => e.trim())
                    .where((e) => e.isNotEmpty)
                    .toList()),
              ),
            ],
          ),

          // ---------- notifications & sounds ----------
          _Section(
            icon: Icons.notifications_outlined,
            title: context.tr('settings.notifications'),
            children: [
              _Switch(
                title: context.tr('settings.dnd'),
                subtitle: context.tr('settings.dndHint'),
                value: s.dndMode,
                onChanged: notifier.setDnd,
              ),
              _Switch(
                title: context.tr('settings.sounds'),
                subtitle: context.tr('settings.soundsHint'),
                value: s.soundEnabled,
                onChanged: notifier.setSoundEnabled,
              ),
              _SliderRow(
                label: context.tr('settings.volume'),
                value: s.soundVolume.toDouble(),
                enabled: s.soundEnabled,
                onChanged: (v) => notifier.setSoundVolume(v.round()),
              ),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: () async {
                  final messenger = ScaffoldMessenger.of(context);
                  final sent = context.tr('settings.toastSent');
                  try {
                    await ipc.request('notify.test');
                    _snack(messenger, sent);
                  } catch (e) {
                    _snack(messenger, '$e', error: true);
                  }
                },
                icon: const Icon(Icons.notifications_active_outlined, size: 16),
                label: Text(context.tr('settings.testToast')),
              ),
            ],
          ),

          // ---------- intel & schedule ----------
          _Section(
            icon: Icons.cloud_sync_outlined,
            title: context.tr('settings.intel'),
            children: [
              Row(children: [
                Expanded(
                  child: Text(context.tr('settings.syncHours'),
                      style: TextStyle(color: AppColors.text, fontSize: 13)),
                ),
                DropdownButton<int>(
                  value: const [1, 3, 6, 12, 24, 48, 168].contains(
                          s.syncIntervalHours)
                      ? s.syncIntervalHours
                      : 6,
                  dropdownColor: AppColors.surface,
                  style: TextStyle(color: AppColors.text, fontSize: 12),
                  items: const [1, 3, 6, 12, 24, 48, 168]
                      .map((h) => DropdownMenuItem(
                            value: h,
                            child: Text('$h h'),
                          ))
                      .toList(),
                  onChanged: (v) {
                    if (v != null) notifier.setSyncHours(v);
                  },
                ),
              ]),
              const SizedBox(height: 8),
              _TextSetting(
                label: context.tr('settings.nvdKey'),
                hint: 'NVD API 2.0 key',
                initial: s.nvdApiKey,
                obscure: true,
                onSave: notifier.setNvdKey,
              ),
              const SizedBox(height: 8),
              Row(children: [
                OutlinedButton.icon(
                  onPressed: () async {
                    final messenger = ScaffoldMessenger.of(context);
                    final done = context.tr('settings.syncDone');
                    try {
                      final res = await ipc.request('sync.now');
                      _snack(messenger, '$done: $res');
                    } catch (e) {
                      _snack(messenger, '$e', error: true);
                    }
                  },
                  icon: const Icon(Icons.sync, size: 16),
                  label: Text(context.tr('settings.syncNow')),
                ),
              ]),
            ],
          ),

          // ---------- integrations ----------
          _Section(
            icon: Icons.hub_outlined,
            title: context.tr('settings.integrations'),
            children: [
              _TextSetting(
                label: context.tr('settings.vtKey'),
                hint: 'VirusTotal API key',
                initial: s.vtApiKey,
                obscure: true,
                onSave: notifier.setVtKey,
              ),
              const SizedBox(height: 8),
              _TextSetting(
                label: context.tr('settings.lmUrl'),
                hint: 'http://127.0.0.1:1234',
                initial: s.lmUrl,
                onSave: (v) => notifier.setLm(v, s.lmModel),
              ),
              const SizedBox(height: 8),
              _TextSetting(
                label: context.tr('settings.lmModel'),
                hint: 'local-model',
                initial: s.lmModel,
                onSave: (v) => notifier.setLm(s.lmUrl, v),
              ),
              const SizedBox(height: 6),
              Text(
                context.tr('settings.lmHint'),
                style: TextStyle(color: AppColors.muted, fontSize: 10.5),
              ),
            ],
          ),

          // ---------- updates ----------
          _Section(
            icon: Icons.system_update_outlined,
            title: context.tr('settings.updates'),
            children: [
              _TextSetting(
                label: context.tr('settings.manifestUrl'),
                hint: 'https://…/mics-manifest.json',
                initial: s.updateManifestUrl,
                onSave: (v) => notifier.setUpdates(v, s.updateChannel),
              ),
              const SizedBox(height: 8),
              Row(children: [
                Expanded(
                  child: Text(context.tr('settings.channel'),
                      style: TextStyle(color: AppColors.text, fontSize: 13)),
                ),
                DropdownButton<String>(
                  value: s.updateChannel,
                  dropdownColor: AppColors.surface,
                  style: TextStyle(color: AppColors.text, fontSize: 12),
                  items: const ['stable', 'beta']
                      .map((c) => DropdownMenuItem(
                            value: c,
                            child: Text(c),
                          ))
                      .toList(),
                  onChanged: (v) {
                    if (v != null) notifier.setUpdates(s.updateManifestUrl, v);
                  },
                ),
              ]),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: () async {
                  final messenger = ScaffoldMessenger.of(context);
                  try {
                    final res = await ipc.request('update.check');
                    _snack(messenger, '$res');
                  } catch (e) {
                    _snack(messenger, '$e', error: true);
                  }
                },
                icon: const Icon(Icons.cloud_download_outlined, size: 16),
                label: Text(context.tr('settings.checkNow')),
              ),
            ],
          ),

          // ---------- engine ----------
          _Section(
            icon: Icons.memory_outlined,
            title: context.tr('settings.engine'),
            children: [
              SelectableText(ipc.resolveEnginePath(),
                  style: AppTheme.mono(size: 11, color: AppColors.cyan)),
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
              const SizedBox(height: 10),
              Wrap(spacing: 8, children: [
                FilledButton.icon(
                  onPressed: () async {
                    final messenger = ScaffoldMessenger.of(context);
                    final on = context.tr('settings.startupOn');
                    try {
                      await ipc.request('service.install');
                      _snack(messenger, on);
                    } catch (e) {
                      _snack(messenger, '$e', error: true);
                    }
                  },
                  icon: const Icon(Icons.power, size: 16),
                  label: Text(context.tr('settings.startupEnable')),
                ),
                OutlinedButton.icon(
                  onPressed: () async {
                    final messenger = ScaffoldMessenger.of(context);
                    final off = context.tr('settings.startupOff');
                    try {
                      await ipc.request('service.remove');
                      _snack(messenger, off);
                    } catch (e) {
                      _snack(messenger, '$e', error: true);
                    }
                  },
                  icon: const Icon(Icons.power_off, size: 16),
                  label: Text(context.tr('settings.startupDisable')),
                ),
              ]),
              const SizedBox(height: 8),
              Text(
                context.tr('settings.settingsFile'),
                style: TextStyle(color: AppColors.muted, fontSize: 10.5),
              ),
              SelectableText('C:\\ProgramData\\MICS\\settings.json',
                  style: AppTheme.mono(size: 10.5, color: AppColors.muted)),
            ],
          ),

          // ---------- about ----------
          _Section(
            icon: Icons.info_outline,
            title: context.tr('settings.about'),
            children: [
              Text('MI CS — Mourad Ibrahim Cyber Security',
                  style: TextStyle(color: AppColors.text, fontSize: 12.5)),
              const SizedBox(height: 4),
              Text(context.tr('app.tagline'),
                  style: TextStyle(color: AppColors.muted, fontSize: 11)),
              const SizedBox(height: 4),
              Text('GPL-3.0-or-later · no telemetry · offline-first',
                  style: TextStyle(color: AppColors.muted, fontSize: 10.5)),
            ],
          ),
        ],
      ),
    );
  }

  /// The messenger is captured before any `await`, so no `BuildContext` is
  /// touched after an async gap.
  void _snack(ScaffoldMessengerState messenger, String message,
      {bool error = false}) {
    messenger.showSnackBar(SnackBar(
      content: Text(message, maxLines: 3, overflow: TextOverflow.ellipsis),
      backgroundColor: error ? AppColors.red.withValues(alpha: 0.85) : null,
    ));
  }
}

// ---------------- building blocks ----------------

class _Section extends StatelessWidget {
  const _Section({
    required this.icon,
    required this.title,
    required this.children,
  });
  final IconData icon;
  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Icon(icon, size: 16, color: AppColors.cyan),
            const SizedBox(width: 8),
            Text(title,
                style: TextStyle(
                    color: AppColors.text,
                    fontSize: 13,
                    fontWeight: FontWeight.w700)),
          ]),
          const SizedBox(height: 12),
          ...children,
        ],
      ),
    );
  }
}

class _Switch extends StatelessWidget {
  const _Switch({
    required this.title,
    required this.subtitle,
    required this.value,
    required this.onChanged,
  });
  final String title;
  final String subtitle;
  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return SwitchListTile(
      contentPadding: EdgeInsets.zero,
      activeThumbColor: AppColors.cyan,
      value: value,
      onChanged: onChanged,
      title: Text(title,
          style: TextStyle(color: AppColors.text, fontSize: 12.5)),
      subtitle: Text(subtitle,
          style: TextStyle(color: AppColors.muted, fontSize: 10.5)),
    );
  }
}

class _SliderRow extends StatelessWidget {
  const _SliderRow({
    required this.label,
    required this.value,
    required this.onChanged,
    this.enabled = true,
  });
  final String label;
  final double value;
  final bool enabled;
  final ValueChanged<double> onChanged;

  @override
  Widget build(BuildContext context) {
    return Row(children: [
      SizedBox(
        width: 90,
        child: Text(label,
            style: TextStyle(color: AppColors.text, fontSize: 12.5)),
      ),
      Expanded(
        child: Slider(
          value: value.clamp(0, 100),
          max: 100,
          divisions: 20,
          activeColor: AppColors.cyan,
          onChanged: enabled ? onChanged : null,
        ),
      ),
      SizedBox(
        width: 40,
        child: Text('${value.round()}',
            textAlign: TextAlign.end,
            style: AppTheme.mono(size: 11, color: AppColors.muted)),
      ),
    ]);
  }
}

/// A text setting that saves on submit or on the check button, and refreshes
/// itself when the engine reports a different value.
class _TextSetting extends StatefulWidget {
  const _TextSetting({
    required this.label,
    required this.initial,
    required this.onSave,
    this.hint = '',
    this.obscure = false,
    this.multiline = false,
  });
  final String label;
  final String initial;
  final String hint;
  final bool obscure;
  final bool multiline;
  final ValueChanged<String> onSave;

  @override
  State<_TextSetting> createState() => _TextSettingState();
}

class _TextSettingState extends State<_TextSetting> {
  late final TextEditingController _controller =
      TextEditingController(text: widget.initial);
  final _focus = FocusNode();

  @override
  void didUpdateWidget(_TextSetting old) {
    super.didUpdateWidget(old);
    if (!_focus.hasFocus && widget.initial != _controller.text) {
      _controller.text = widget.initial;
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    _focus.dispose();
    super.dispose();
  }

  void _save() {
    widget.onSave(_controller.text.trim());
    _focus.unfocus();
  }

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: _controller,
      focusNode: _focus,
      obscureText: widget.obscure,
      maxLines: widget.multiline ? 4 : 1,
      style: widget.multiline
          ? AppTheme.mono(size: 11)
          : TextStyle(color: AppColors.text, fontSize: 12),
      decoration: InputDecoration(
        isDense: true,
        labelText: widget.label,
        hintText: widget.hint,
        suffixIcon: IconButton(
          tooltip: 'Save',
          icon: Icon(Icons.check, size: 16, color: AppColors.green),
          onPressed: _save,
        ),
      ),
      onSubmitted: (_) => _save(),
    );
  }
}
