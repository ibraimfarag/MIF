import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/audio/sound_service.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/crash_reports.dart';
import 'package:mics_app/core/ipc/helper_status.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/ipc/package_integrity.dart';
import 'package:mics_app/core/sync/sync_status.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/models/crash_models.dart';

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
    // What the packs actually loaded, for the one fact a picker cannot show:
    // a bundled language whose folder this build does not carry (D-050).
    final i18n =
        ref.watch(i18nProvider).value ?? const <String, Map<String, String>>{};

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
              Row(children: [
                Icon(Icons.translate, size: 16, color: AppColors.muted),
                const SizedBox(width: 8),
                Text(context.tr('settings.language'),
                    style: TextStyle(color: AppColors.text, fontSize: 13)),
                const Spacer(),
                DropdownButton<AppLang>(
                  value: s.lang,
                  dropdownColor: AppColors.surface,
                  underline: const SizedBox.shrink(),
                  borderRadius: BorderRadius.circular(10),
                  items: [
                    for (final lang in AppLang.all)
                      DropdownMenuItem(
                        value: lang,
                        child: Text(lang.nativeName,
                            style: TextStyle(
                                color: AppColors.text,
                                fontSize: 13,
                                // Each name is shown in its own script, which is
                                // the only way a user who cannot read the current
                                // language can find theirs.
                                fontFamilyFallback: const ['Segoe UI'])),
                      ),
                  ],
                  onChanged: (lang) {
                    if (lang != null) notifier.setLang(lang);
                  },
                ),
              ]),
              // This line is always English in practice: an unpacked tag is
              // exactly the case that renders English (D-049), so the pack that
              // could translate it is the one that is missing. The key exists in
              // every language anyway - the parity test requires it.
              if (s.langPackMissing)
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Text(
                    context
                        .tr('settings.languageMissing')
                        .replaceAll('{tag}', s.storedLangTag),
                    style: TextStyle(color: AppColors.orange, fontSize: 12),
                  ),
                ),
              // The sibling fact of the line above, for a language that *is*
              // bundled: its folder is not in this build's asset list, so it
              // loaded as an empty table and every key of it falls back. The
              // stored tag is not what is wrong here - the build is (D-050).
              if (!packLoaded(i18n, s.lang.code))
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Text(
                    context
                        .tr('settings.languagePackMissing')
                        .replaceAll('{language}', s.lang.nativeName),
                    style: TextStyle(color: AppColors.orange, fontSize: 12),
                  ),
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
                title: context.tr('settings.closeToTray'),
                subtitle: context.tr('settings.closeToTrayHint'),
                value: s.closeToTray,
                onChanged: notifier.setCloseToTray,
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
              // Opt-in, per-user, no elevation (D-054). The engine writes the
              // keys; turning it off removes exactly the keys it wrote.
              _Switch(
                title: context.tr('settings.explorerMenu'),
                subtitle: context.tr('settings.explorerMenuHint'),
                value: s.explorerMenu,
                onChanged: notifier.setExplorerMenu,
              ),
              const SizedBox(height: 8),
              Row(children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(context.tr('settings.scanHours'),
                          style: TextStyle(color: AppColors.text, fontSize: 13)),
                      Text(
                        context.tr('settings.scanHoursHint'),
                        style: TextStyle(color: AppColors.muted, fontSize: 11),
                      ),
                    ],
                  ),
                ),
                DropdownButton<int>(
                  value: const [0, 6, 12, 24, 72, 168]
                          .contains(s.scanIntervalHours)
                      ? s.scanIntervalHours
                      : 0,
                  dropdownColor: AppColors.surface,
                  style: TextStyle(color: AppColors.text, fontSize: 12),
                  items: const [0, 6, 12, 24, 72, 168]
                      .map((h) => DropdownMenuItem(
                            value: h,
                            child: Text(h == 0
                                ? context.tr('settings.scanOff')
                                : '$h h'),
                          ))
                      .toList(),
                  onChanged: (v) {
                    if (v != null) notifier.setScanHours(v);
                  },
                ),
              ]),
              const SizedBox(height: 8),
              _TextSetting(
                label: context.tr('settings.scanTarget'),
                hint: context.tr('settings.scanTargetHint'),
                initial: s.scanTarget,
                onSave: notifier.setScanTarget,
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
                title: context.tr('settings.toasts'),
                subtitle: context.tr('settings.toastsHint'),
                value: s.toastEnabled,
                onChanged: notifier.setToastEnabled,
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
              Wrap(spacing: 8, children: [
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
                  icon: const Icon(Icons.notifications_active_outlined,
                      size: 16),
                  label: Text(context.tr('settings.testToast')),
                ),
                OutlinedButton.icon(
                  onPressed: () => ref
                      .read(soundServiceProvider)
                      .play(SoundCue.critical, volume: s.soundVolume),
                  icon: const Icon(Icons.music_note_outlined, size: 16),
                  label: Text(context.tr('settings.testSound')),
                ),
              ]),
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
              _TextSetting(
                label: context.tr('settings.iocFeedUrl'),
                hint: 'https://…/hashes.csv',
                initial: s.iocFeedUrl,
                onSave: (v) => notifier.setIocFeed(v, s.iocFeedKey),
              ),
              const SizedBox(height: 8),
              _TextSetting(
                label: context.tr('settings.iocFeedKey'),
                hint: 'Auth-Key',
                initial: s.iocFeedKey,
                obscure: true,
                onSave: (v) => notifier.setIocFeed(s.iocFeedUrl, v),
              ),
              const SizedBox(height: 4),
              Text(
                context.tr('settings.iocFeedHint'),
                style: TextStyle(color: AppColors.muted, fontSize: 11),
              ),
              const SizedBox(height: 8),
              Row(children: [
                OutlinedButton.icon(
                  onPressed: () async {
                    final messenger = ScaffoldMessenger.of(context);
                    final done = context.tr('settings.syncDone');
                    try {
                      await ref.read(syncStatusProvider.notifier).syncNow();
                      _snack(messenger, done);
                    } catch (e) {
                      _snack(messenger, '$e', error: true);
                    }
                  },
                  icon: const Icon(Icons.sync, size: 16),
                  label: Text(context.tr('settings.syncNow')),
                ),
                const SizedBox(width: 8),
                _SyncLive(),
              ]),
            ],
          ),

          // ---------- updates ----------
          _Section(
            icon: Icons.system_update_outlined,
            title: context.tr('settings.updates'),
            children: [
              _TextSetting(
                label: context.tr('settings.manifestUrl'),
                hint: context.tr('settings.manifestUrlDefault'),
                initial: s.updateManifestUrl,
                onSave: (v) => notifier.setUpdates(v, s.updateChannel),
              ),
              const SizedBox(height: 4),
              // Empty stopped meaning "off": the engine reads the channel's own
              // feed unless the user typed one (D-046), so the sentence below has
              // to say that — and that nothing is fetched on its own.
              Text(context.tr('settings.manifestHint'),
                  style: TextStyle(color: AppColors.muted, fontSize: 10.5)),
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
              _UpdatePanel(
                manifestUrl: s.updateManifestUrl,
                channel: s.updateChannel,
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
              _EngineFailureLine(ipc: ipc),
              const SizedBox(height: 10),
              _HelperCard(ipc: ipc),
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

          // ---------- diagnostics: the bug-id surface (ز2-ج) ----------
          _Section(
            icon: Icons.bug_report_outlined,
            title: context.tr('settings.diagnostics'),
            children: [
              Text(
                context.tr('settings.diagnosticsHint'),
                style: TextStyle(color: AppColors.muted, fontSize: 10.5),
              ),
              const SizedBox(height: 8),
              const _DiagnosticsCard(),
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
              const SizedBox(height: 8),
              const _IntegrityLine(),
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

/// What the engine said when it refused to start.
///
/// The engine runs detached, so a refusal — most of all the Low-integrity folder
/// one, which a sandbox or a web root produces — goes to a stderr nobody reads
/// and the user is left staring at "engine missing" next to a retry button that
/// cannot succeed. `EngineIpc` re-runs the engine once with stderr piped to
/// recover that sentence; this shows it where the state is already displayed.
class _EngineFailureLine extends StatelessWidget {
  const _EngineFailureLine({required this.ipc});

  final EngineIpc ipc;

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<EngineState>(
      stream: ipc.statusStream,
      initialData: ipc.state,
      builder: (context, snapshot) {
        final reason = ipc.lastFailure;
        if (snapshot.data != EngineState.engineMissing || reason == null) {
          return const SizedBox.shrink();
        }
        return Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(context.tr('settings.engine.lastError'),
                  style: TextStyle(color: AppColors.red, fontSize: 12)),
              const SizedBox(height: 3),
              SelectableText(reason,
                  style: AppTheme.mono(size: 11, color: AppColors.muted)),
            ],
          ),
        );
      },
    );
  }
}

/// Is this copy the one that was published? (ج2, D-025)
///
/// One line, always in the same place: green when the engine proved it, quiet
/// when the only unknown is whether *this machine* trusts the release
/// certificate (a self-signed build is not a fault), and the notice when the
/// engine's own signed manifest disagrees with the files beside it. The alert
/// card raised at startup says which file moved; this says what to do.
class _IntegrityLine extends ConsumerWidget {
  const _IntegrityLine();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final integrity =
        ref.watch(packageIntegrityProvider).value ?? PackageIntegrity.unknown;
    if (!integrity.known) return const SizedBox.shrink();

    late final IconData icon;
    late final Color color;
    late final String copy;
    switch (integrity) {
      case PackageIntegrity.ok:
        icon = Icons.verified_user_outlined;
        color = AppColors.green;
        copy = context.tr('settings.integrityOk');
        break;
      case PackageIntegrity.untrustedCertificate:
        icon = Icons.gpp_maybe_outlined;
        color = AppColors.muted;
        copy = context.tr('settings.integrityUntrusted');
        break;
      case PackageIntegrity.unverified:
      case PackageIntegrity.unknown:
        icon = Icons.gpp_bad_outlined;
        color = AppColors.orange;
        copy = context.tr('settings.integrityUnverified');
        break;
    }

    final line = Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, size: 14, color: color),
        const SizedBox(width: 6),
        Expanded(
          child: Text(copy, style: TextStyle(color: color, fontSize: 10.5)),
        ),
      ],
    );
    if (!integrity.warns) return line;
    // The notice wears the error banner's pair - orange on the red 8 % fill -
    // which is the contrast the audit already measures.
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: AppColors.red.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.red.withValues(alpha: 0.4)),
      ),
      child: line,
    );
  }
}

/// The privileged helper (D-007): one install press, then every admin operation
/// — firewall, hosts, hardening — runs without a UAC prompt.
class _HelperCard extends ConsumerStatefulWidget {
  const _HelperCard({required this.ipc});

  final EngineIpc ipc;

  @override
  ConsumerState<_HelperCard> createState() => _HelperCardState();
}

class _HelperCardState extends ConsumerState<_HelperCard> {
  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    final status =
        ref.watch(helperStatusProvider).value ?? HelperStatus.empty;
    final color = status.usable
        ? AppColors.green
        : status.installed
            ? AppColors.orange
            : AppColors.muted;
    final state = context.tr('helper.state.${_stateKey(status)}');
    final version = status.version == null ? '' : ' · v${status.version}';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(children: [
          Icon(
            status.usable ? Icons.verified_user : Icons.shield_outlined,
            size: 14,
            color: color,
          ),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              '${context.tr('helper.title')}: $state$version',
              style: TextStyle(color: color, fontSize: 12),
            ),
          ),
        ]),
        const SizedBox(height: 6),
        Text(
          context.tr('helper.hint'),
          style: TextStyle(color: AppColors.muted, fontSize: 10.5),
        ),
        const SizedBox(height: 8),
        Wrap(spacing: 8, children: [
          FilledButton.icon(
            onPressed: _busy ? null : () => _run(install: true),
            icon: _busy
                ? const SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.admin_panel_settings_outlined, size: 16),
            label: Text(context.tr(
                status.installed ? 'helper.repair' : 'helper.install')),
          ),
          if (status.installed)
            OutlinedButton.icon(
              onPressed: _busy ? null : () => _run(install: false),
              icon: const Icon(Icons.delete_outline, size: 16),
              label: Text(context.tr('helper.remove')),
            ),
        ]),
      ],
    );
  }

  /// Maps the engine's service state onto a translation key.
  String _stateKey(HelperStatus status) {
    if (status.usable) return 'ready';
    if (status.reachable) return 'unelevated';
    if (status.installed) return 'not_running';
    return 'missing';
  }

  Future<void> _run({required bool install}) async {
    final messenger = ScaffoldMessenger.of(context);
    final notifier = ref.read(helperStatusProvider.notifier);
    final done = context.tr(install ? 'helper.installDone' : 'helper.removeDone');
    setState(() => _busy = true);
    try {
      if (install) {
        await notifier.install();
      } else {
        await notifier.remove();
      }
      messenger.showSnackBar(SnackBar(content: Text(done)));
    } catch (e) {
      messenger.showSnackBar(SnackBar(
        content: Text('$e', maxLines: 3, overflow: TextOverflow.ellipsis),
        backgroundColor: AppColors.red.withValues(alpha: 0.85),
      ));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }
}

/// Settings → Diagnostics (ز2-ج): the reports the engine wrote for a panic, an
/// unclean exit or a hang.
///
/// It lists them (`crash.list`), opens one (`crash.get`), copies the text a user
/// can paste — the bug id on the first line — and deletes it (`crash.delete`).
/// The reports directory belongs to the engine: this widget never opens a file,
/// and nothing here sends anything anywhere.
class _DiagnosticsCard extends ConsumerStatefulWidget {
  const _DiagnosticsCard();

  @override
  ConsumerState<_DiagnosticsCard> createState() => _DiagnosticsCardState();
}

class _DiagnosticsCardState extends ConsumerState<_DiagnosticsCard> {
  /// The row that is open, and what `crash.get` answered for it.
  String? _openId;
  CrashReport? _open;

  Future<void> _toggle(CrashSummary row) async {
    final messenger = ScaffoldMessenger.of(context);
    final failed = context.tr('diagnostics.openFailed');
    if (_openId == row.bugId) {
      setState(() {
        _openId = null;
        _open = null;
      });
      return;
    }
    setState(() {
      _openId = row.bugId;
      _open = null;
    });
    try {
      final report =
          await ref.read(crashReportsProvider.notifier).open(row.bugId);
      if (!mounted || _openId != row.bugId) return;
      setState(() => _open = report);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _openId = null;
        _open = null;
      });
      _failed(messenger, '$failed: $e');
    }
  }

  Future<void> _copy(CrashReport report) async {
    final messenger = ScaffoldMessenger.of(context);
    final copied = context.tr('diagnostics.copied');
    final failed = context.tr('diagnostics.copyFailed');
    try {
      await Clipboard.setData(ClipboardData(text: report.pasteText));
      _inform(messenger, copied);
    } catch (e) {
      _failed(messenger, '$failed: $e');
    }
  }

  Future<void> _delete(String bugId) async {
    final messenger = ScaffoldMessenger.of(context);
    final done = context.tr('diagnostics.deleted');
    try {
      await ref.read(crashReportsProvider.notifier).delete(bugId);
      if (!mounted) return;
      if (_openId == bugId) {
        setState(() {
          _openId = null;
          _open = null;
        });
      }
      _inform(messenger, done);
    } catch (e) {
      _failed(messenger, '$e');
    }
  }

  /// The messengers are handed in from a frame that had a `BuildContext`: no
  /// context is touched after an await.
  void _inform(ScaffoldMessengerState messenger, String message) {
    messenger.showSnackBar(SnackBar(
      content: Text(message, maxLines: 3, overflow: TextOverflow.ellipsis),
    ));
  }

  void _failed(ScaffoldMessengerState messenger, String message) {
    messenger.showSnackBar(SnackBar(
      content: Text(message, maxLines: 3, overflow: TextOverflow.ellipsis),
      backgroundColor: AppColors.red.withValues(alpha: 0.85),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return ref.watch(crashReportsProvider).when(
          loading: () => const Padding(
            padding: EdgeInsets.symmetric(vertical: 4),
            child: SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2)),
          ),
          error: (e, _) => Text(
            '${context.tr('diagnostics.loadFailed')}: $e',
            style: TextStyle(color: AppColors.orange, fontSize: 11),
          ),
          data: (reports) => reports.isEmpty
              ? Text(context.tr('diagnostics.empty'),
                  style: TextStyle(color: AppColors.muted, fontSize: 11.5))
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [for (final row in reports) _row(row)],
                ),
        );
  }

  Widget _row(CrashSummary row) {
    final open = _openId == row.bugId;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ListTile(
          contentPadding: EdgeInsets.zero,
          onTap: () => _toggle(row),
          leading: Icon(_icon(row.kind), size: 18, color: _kindColor(row.kind)),
          title: Text(row.bugId,
              style: AppTheme.mono(size: 11.5, color: AppColors.text)),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(row.message,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(color: AppColors.muted, fontSize: 11)),
              const SizedBox(height: 2),
              Text(_meta(row),
                  style: AppTheme.mono(size: 10, color: AppColors.muted)),
            ],
          ),
          trailing: Icon(open ? Icons.expand_less : Icons.expand_more,
              size: 18, color: AppColors.muted),
        ),
        if (open)
          _open == null ? _opening() : _detail(_open!),
        const Divider(height: 8),
      ],
    );
  }

  Widget _opening() => const Padding(
        padding: EdgeInsets.only(left: 2, top: 2, bottom: 8),
        child: SizedBox(
            width: 14,
            height: 14,
            child: CircularProgressIndicator(strokeWidth: 2)),
      );

  /// The whole report as the user will paste it - the first line is the bug id
  /// - with the two actions the section promises.
  Widget _detail(CrashReport report) {
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(top: 2, bottom: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SelectableText(report.pasteText,
              style: AppTheme.mono(size: 10.5, color: AppColors.text)),
          const SizedBox(height: 4),
          Row(children: [
            IconButton(
              tooltip: context.tr('diagnostics.copy'),
              onPressed: () => _copy(report),
              icon: const Icon(Icons.copy_all_outlined, size: 16),
              color: AppColors.cyan,
            ),
            IconButton(
              tooltip: context.tr('diagnostics.delete'),
              onPressed: () => _delete(report.bugId),
              icon: const Icon(Icons.delete_outline, size: 16),
              color: AppColors.red,
            ),
          ]),
        ],
      ),
    );
  }

  /// The one line of facts under the message: the engine's own kind, how often
  /// the same failure was seen, and when it was last seen (UTC, as the engine
  /// writes it).
  String _meta(CrashSummary row) {
    final seen = row.occurrences > 1
        ? '${context.tr('diagnostics.seen').replaceAll('{count}', '${row.occurrences}')} · '
        : '';
    return '${row.kind} · $seen${row.lastSeen}';
  }

  IconData _icon(String kind) => switch (kind) {
        'panic' => Icons.error_outline,
        'unclean-exit' => Icons.power_off,
        'hang' => Icons.hourglass_bottom,
        _ => Icons.bug_report_outlined,
      };

  Color _kindColor(String kind) => switch (kind) {
        'panic' => AppColors.red,
        'unclean-exit' => AppColors.orange,
        'hang' => AppColors.yellow,
        _ => AppColors.muted,
      };
}

/// Live connectivity + intel freshness, next to the manual sync button.
class _SyncLive extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final status = ref.watch(syncStatusProvider).value ?? SyncStatus.empty;
    final color = status.online ? AppColors.green : AppColors.orange;
    final text = status.neverSynced
        ? context.tr('sync.never')
        : context
            .tr('sync.intel')
            .replaceAll('{age}', status.ageLabel);
    return Row(mainAxisSize: MainAxisSize.min, children: [
      Container(
          width: 7,
          height: 7,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
      const SizedBox(width: 6),
      Text(
        '${status.online ? context.tr('sync.online') : context.tr('sync.offline')}'
        ' · $text · ${context.tr('sync.hashes').replaceAll('{count}', '${status.iocHashes}')}',
        style: TextStyle(color: AppColors.muted, fontSize: 10.5),
      ),
    ]);
  }
}

/// Update flow: check → show version + notes → download → apply.
class _UpdatePanel extends ConsumerStatefulWidget {
  const _UpdatePanel({required this.manifestUrl, required this.channel});
  final String manifestUrl;
  final String channel;

  @override
  ConsumerState<_UpdatePanel> createState() => _UpdatePanelState();
}

class _UpdatePanelState extends ConsumerState<_UpdatePanel> {
  bool _checking = false;
  bool _installing = false;
  Map<String, dynamic>? _info;
  String? _error;

  Future<void> _check() async {
    setState(() {
      _checking = true;
      _error = null;
    });
    try {
      final res = await ref.read(engineIpcProvider).request('update.check');
      setState(() => _info = (res as Map).cast<String, dynamic>());
    } catch (e) {
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _checking = false);
    }
  }

  Future<void> _install() async {
    final messenger = ScaffoldMessenger.of(context);
    setState(() {
      _installing = true;
      _error = null;
    });
    try {
      // A release ZIP can take minutes on a slow line; the default 120 s
      // deadline would abandon the wait while the engine keeps downloading.
      await ref
          .read(engineIpcProvider)
          .request('update.download', null, const Duration(minutes: 10));
      await ref.read(engineIpcProvider).request('update.apply');
      if (!mounted) return;
      messenger.showSnackBar(
          SnackBar(content: Text(context.tr('update.installed'))));
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = '$e');
      messenger.showSnackBar(SnackBar(
          content: Text('${context.tr('update.failed')}: $e'),
          backgroundColor: AppColors.red.withValues(alpha: 0.85)));
    } finally {
      if (mounted) setState(() => _installing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final status = _info?['status'] as String?;
    final current = _info?['current']?.toString() ?? '';
    final latest = _info?['latest']?.toString() ?? '';
    final notes = _info?['notes_en']?.toString() ?? '';
    // Which feed answered, not which feed was configured: with an empty URL the
    // engine reads its channel's own feed (D-046), and the answer says which one —
    // an update check nobody can check is just a claim.
    final feed = _info?['manifest_url']?.toString() ?? widget.manifestUrl;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(children: [
          OutlinedButton.icon(
            onPressed: _checking ? null : _check,
            icon: _checking
                ? const SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.cloud_download_outlined, size: 16),
            label: Text(context.tr('settings.checkNow')),
          ),
          const SizedBox(width: 10),
          Text(widget.channel,
              style: AppTheme.mono(size: 10, color: AppColors.muted)),
        ]),
        if (_error != null) ...[
          const SizedBox(height: 8),
          Text(_error!, style: TextStyle(color: AppColors.orange, fontSize: 11)),
        ],
        if (status == 'disabled') ...[
          const SizedBox(height: 8),
          // The engine's own reason: the only way to reach this state is the
          // MICS_UPDATE_MANIFEST_URL=off hook, and inventing a second wording for
          // it here would be one more sentence to keep true.
          Text(_info?['detail']?.toString() ?? '',
              style: TextStyle(color: AppColors.muted, fontSize: 11)),
        ],
        if (status != null && status != 'disabled' && feed.isNotEmpty) ...[
          const SizedBox(height: 6),
          Text('${context.tr('settings.manifestUrl')}: $feed',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: AppTheme.mono(size: 10, color: AppColors.muted)),
        ],
        if (status == 'up_to_date') ...[
          const SizedBox(height: 8),
          Row(children: [
            Icon(Icons.check_circle, size: 14, color: AppColors.green),
            const SizedBox(width: 6),
            Text(
                '${context.tr('update.upToDate')} · '
                '${context.tr('update.current').replaceAll('{version}', current)}',
                style: TextStyle(color: AppColors.text, fontSize: 11.5)),
          ]),
        ],
        if (status == 'available') ...[
          const SizedBox(height: 8),
          Text(
              context
                  .tr('update.available')
                  .replaceAll('{version}', latest),
              style: TextStyle(
                  color: AppColors.cyan,
                  fontSize: 12,
                  fontWeight: FontWeight.w700)),
          const SizedBox(height: 4),
          Text(context.tr('update.current').replaceAll('{version}', current),
              style: AppTheme.mono(size: 10.5, color: AppColors.muted)),
          if (notes.isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(context.tr('update.notes'),
                style: TextStyle(color: AppColors.text, fontSize: 11)),
            Text(notes,
                maxLines: 4,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: AppColors.muted, fontSize: 10.5)),
          ],
          const SizedBox(height: 8),
          FilledButton.icon(
            onPressed: _installing ? null : _install,
            icon: _installing
                ? const SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.system_update_alt, size: 16),
            label: Text(context.tr('update.download')),
          ),
        ],
      ],
    );
  }
}


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
      // The switches below are ListTiles, and a ListTile paints its ink splash
      // on the nearest Material ancestor. Without this transparent Material the
      // decorated Container above is that nearest surface, so every switch lost
      // its splash — and Flutter asserts about it on every Settings render
      // ("ListTile background color or ink splashes may be invisible").
      child: Material(
        type: MaterialType.transparency,
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
