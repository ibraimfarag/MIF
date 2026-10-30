import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/sync/sync_status.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/providers/providers.dart';
import 'package:window_manager/window_manager.dart';

/// MI CS shell — macOS-style custom title bar (traffic lights + drag area),
/// branded header with live score, omnibox and quick controls, and a
/// 13-module navigation rail.
class AppShell extends ConsumerStatefulWidget {
  const AppShell({super.key, required this.child});
  final Widget child;

  @override
  ConsumerState<AppShell> createState() => _AppShellState();
}

class _NavDest {
  final String route;
  final IconData icon;
  final String labelKey;
  final Color accent;
  const _NavDest(this.route, this.icon, this.labelKey, this.accent);
}

final _navItems = [
  _NavDest('/dashboard', Icons.shield_outlined, 'nav.dashboard', AppColors.cyan),
  _NavDest('/audit', Icons.fact_check_outlined, 'nav.audit', AppColors.green),
  _NavDest('/scanner', Icons.bug_report_outlined, 'nav.scanner', AppColors.red),
  _NavDest('/network', Icons.lan_outlined, 'nav.network', AppColors.orange),
  _NavDest('/ids', Icons.radar_outlined, 'nav.ids', AppColors.orange),
  _NavDest('/vulns', Icons.gpp_maybe_outlined, 'nav.vulns', AppColors.red),
  _NavDest('/guard', Icons.monitor_heart_outlined, 'nav.guard', AppColors.green),
  _NavDest('/canaries', Icons.egg_outlined, 'nav.canaries', AppColors.orange),
  _NavDest('/hardening', Icons.lock_reset_outlined, 'nav.hardening', AppColors.cyan),
  _NavDest('/incidents', Icons.timeline_outlined, 'nav.incidents', AppColors.red),
  _NavDest('/reports', Icons.description_outlined, 'nav.reports', AppColors.cyan),
  _NavDest('/intel', Icons.cloud_sync_outlined, 'nav.intel', AppColors.cyan),
  _NavDest('/settings', Icons.settings_outlined, 'nav.settings', AppColors.muted),
];

class _AppShellState extends ConsumerState<AppShell> with WindowListener {
  @override
  void initState() {
    super.initState();
    windowManager.addListener(this);
  }

  @override
  void dispose() {
    windowManager.removeListener(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final engineAsync = ref.watch(engineStateProvider);
    final engineState =
        engineAsync.value ?? ref.read(engineIpcProvider).state;
    final rtl = ref.watch(rtlProvider);
    final lang = ref.watch(localeProvider);

    final loc = GoRouterState.of(context).uri.path;
    final selectedIndex =
        _navItems.indexWhere((d) => loc.startsWith(d.route)).clamp(0, 12);

    return Directionality(
      textDirection: rtl ? TextDirection.rtl : TextDirection.ltr,
      child: Scaffold(
        body: Container(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                AppColors.background,
                Color.lerp(AppColors.background, AppColors.cyan, 0.03)!,
              ],
            ),
          ),
          child: Column(
            children: [
              _TitleBar(lang: lang, engineState: engineState),
              Expanded(
                child: Row(
                  children: [
                    _BrandRail(selectedIndex: selectedIndex),
                    VerticalDivider(width: 1, color: AppColors.border),
                    Expanded(child: widget.child),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------- intel / connectivity chip ----------------

/// OFFLINE badge + intelligence freshness (spec section 6/7).
///
/// Offline is a first-class state: the app keeps working with the last synced
/// intel, and the chip says exactly how old that intel is.
class _IntelChip extends ConsumerWidget {
  const _IntelChip();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final status = ref.watch(syncStatusProvider).value ?? SyncStatus.empty;
    final online = status.online;
    final color = online ? AppColors.green : AppColors.orange;
    final label = online ? context.tr('sync.online') : context.tr('sync.offline');
    final freshness = status.neverSynced
        ? context.tr('sync.never')
        : context.tr('sync.intel').replaceAll('{age}', status.ageLabel);

    return Tooltip(
      message: '${context.tr('sync.tooltip')}\n'
          '${context.tr('sync.hashes').replaceAll('{count}', '${status.iocHashes}')}\n'
          '${context.tr('sync.every').replaceAll('{hours}', '${status.intervalHours}')}',
      child: InkWell(
        borderRadius: BorderRadius.circular(999),
        onTap: () async {
          final messenger = ScaffoldMessenger.of(context);
          final done = context.tr('sync.done');
          try {
            await ref.read(syncStatusProvider.notifier).syncNow();
            messenger.showSnackBar(SnackBar(
                content: Text(done), duration: const Duration(seconds: 2)));
          } catch (e) {
            messenger.showSnackBar(SnackBar(content: Text('$e')));
          }
        },
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(999),
            border: Border.all(color: color.withValues(alpha: 0.45)),
            color: color.withValues(alpha: 0.08),
          ),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Container(
              width: 7,
              height: 7,
              decoration: BoxDecoration(color: color, shape: BoxShape.circle),
            ),
            const SizedBox(width: 6),
            Text(label, style: TextStyle(color: color, fontSize: 11)),
            const SizedBox(width: 8),
            Container(width: 1, height: 11, color: AppColors.border),
            const SizedBox(width: 8),
            Icon(Icons.storage_outlined, size: 11, color: AppColors.muted),
            const SizedBox(width: 4),
            Text(freshness,
                style: TextStyle(color: AppColors.muted, fontSize: 10.5)),
          ]),
        ),
      ),
    );
  }
}

// ---------------- title bar (macOS style) ----------------

class _TitleBar extends ConsumerWidget {
  const _TitleBar({required this.lang, required this.engineState});
  final AppLang lang;
  final EngineState engineState;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final (color, label) = switch (engineState) {
      EngineState.running => (AppColors.green, 'engine.running'),
      EngineState.reconnecting => (AppColors.orange, 'engine.reconnecting'),
      EngineState.engineMissing => (AppColors.red, 'engine.missing'),
      EngineState.stopped => (AppColors.muted, 'engine.stopped'),
    };

    return GestureDetector(
      onPanStart: (_) => windowManager.startDragging(),
      onDoubleTap: () async {
        (await windowManager.isMaximized())
            ? windowManager.unmaximize()
            : windowManager.maximize();
      },
      child: Container(
        height: 52,
        color: AppColors.surface,
        child: Row(
          children: [
            const SizedBox(width: 14),
            // macOS traffic lights.
            _TrafficLight(
                color: const Color(0xFFFF5F57), onTap: () => windowManager.close()),
            const SizedBox(width: 8),
            _TrafficLight(
                color: const Color(0xFFFEBC2E), onTap: () => windowManager.minimize()),
            const SizedBox(width: 8),
            _TrafficLight(
                color: const Color(0xFF28C840),
                onTap: () async {
                  (await windowManager.isMaximized())
                      ? windowManager.unmaximize()
                      : windowManager.maximize();
                }),
            const SizedBox(width: 14),
            _BrandMark(),
            const SizedBox(width: 10),
            Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('MIF',
                    style: TextStyle(
                        color: AppColors.text,
                        fontWeight: FontWeight.w800,
                        fontSize: 13.5,
                        height: 1.0)),
                Text(context.tr('app.tagline'),
                    style: TextStyle(
                        color: AppColors.muted, fontSize: 8.5, height: 1.2)),
              ],
            ),
            const SizedBox(width: 14),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(999),
                border: Border.all(color: color.withValues(alpha: 0.5)),
                color: color.withValues(alpha: 0.08),
              ),
              child: Row(children: [
                Container(width: 7, height: 7,
                    decoration:
                        BoxDecoration(color: color, shape: BoxShape.circle)),
                const SizedBox(width: 6),
                Text('${context.tr('state.engine')}: ${context.tr(label)}',
                    style: TextStyle(color: color, fontSize: 11)),
              ]),
            ),
            const Spacer(),
            const _IntelChip(),
            const SizedBox(width: 8),
            if (ref.watch(settingsProvider).value?.nlBarEnabled ?? true)
              const _Omnibox(),
            const SizedBox(width: 8),
            _HeaderIcon(
              icon: (ref.watch(settingsProvider).value?.themeMode ??
                          ThemeMode.dark) ==
                      ThemeMode.dark
                  ? Icons.light_mode_outlined
                  : Icons.dark_mode_outlined,
              tooltip: context.tr('shell.theme'),
              onTap: () {
                final cur = ref.read(settingsProvider).value?.themeMode ??
                    ThemeMode.dark;
                ref.read(settingsProvider.notifier).setThemeMode(
                    cur == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark);
              },
            ),
            _HeaderIcon(
              icon: Icons.language,
              tooltip: lang == AppLang.ar ? 'English' : 'العربية',
              onTap: () {
                ref.read(settingsProvider.notifier).setLang(
                    lang == AppLang.ar ? AppLang.en : AppLang.ar);
              },
            ),
            const SizedBox(width: 10),
          ],
        ),
      ),
    );
  }
}

class _TrafficLight extends StatefulWidget {
  const _TrafficLight({required this.color, required this.onTap});
  final Color color;
  final VoidCallback onTap;

  @override
  State<_TrafficLight> createState() => _TrafficLightState();
}

class _TrafficLightState extends State<_TrafficLight> {
  bool _hover = false;
  @override
  Widget build(BuildContext context) {
    return MouseRegion(
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: GestureDetector(
        onTap: widget.onTap,
        child: Container(
          width: 12,
          height: 12,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: _hover ? widget.color : widget.color.withValues(alpha: 0.55),
            border: Border.all(
                color: AppColors.border.withValues(alpha: 0.6), width: 0.5),
          ),
          child: _hover
              ? Icon(Icons.close, size: 8, color: Colors.black.withValues(alpha: 0.55))
              : null,
        ),
      ),
    );
  }
}

class _BrandMark extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      width: 30,
      height: 30,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [AppColors.cyan, AppColors.green],
        ),
        borderRadius: BorderRadius.circular(9),
        boxShadow: [
          BoxShadow(
              color: AppColors.cyan.withValues(alpha: 0.35), blurRadius: 10),
        ],
      ),
      child: const Icon(Icons.shield, color: Colors.white, size: 17),
    );
  }
}

class _HeaderIcon extends StatelessWidget {
  const _HeaderIcon(
      {required this.icon, required this.tooltip, required this.onTap});
  final IconData icon;
  final String tooltip;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: tooltip,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Icon(icon, size: 17, color: AppColors.muted),
        ),
      ),
    );
  }
}

// ---------------- brand rail ----------------

class _BrandRail extends StatelessWidget {
  const _BrandRail({required this.selectedIndex});
  final int selectedIndex;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 96,
      color: AppColors.surface,
      child: SingleChildScrollView(
        child: Column(
          children: [
            const SizedBox(height: 8),
            for (final (i, d) in _navItems.indexed)
              _RailItem(dest: d, selected: i == selectedIndex),
            const SizedBox(height: 8),
          ],
        ),
      ),
    );
  }
}

class _RailItem extends StatefulWidget {
  const _RailItem({required this.dest, required this.selected});
  final _NavDest dest;
  final bool selected;

  @override
  State<_RailItem> createState() => _RailItemState();
}

class _RailItemState extends State<_RailItem> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final d = widget.dest;
    final active = widget.selected;
    final color = active ? d.accent : (_hover ? AppColors.text : AppColors.muted);
    return MouseRegion(
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: GestureDetector(
        onTap: () => context.go(d.route),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          margin: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
          padding: const EdgeInsets.symmetric(vertical: 8),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(12),
            color: active
                ? d.accent.withValues(alpha: 0.12)
                : _hover
                    ? AppColors.border.withValues(alpha: 0.3)
                    : Colors.transparent,
            border: Border.all(
                color: active ? d.accent.withValues(alpha: 0.35) : Colors.transparent),
          ),
          child: Column(
            children: [
              Stack(
                clipBehavior: Clip.none,
                children: [
                  Icon(d.icon, size: 20, color: color),
                  if (active)
                    PositionedDirectional(
                      start: -8,
                      top: 2,
                      bottom: 2,
                      child: Container(width: 3,
                          decoration: BoxDecoration(
                              color: d.accent,
                              borderRadius: BorderRadius.circular(2))),
                    ),
                ],
              ),
              const SizedBox(height: 4),
              Text(context.tr(d.labelKey),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                      color: color,
                      fontSize: 9.5,
                      fontWeight: active ? FontWeight.w700 : FontWeight.w500)),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------- omnibox ----------------

/// Natural-language command bar (nl.command): Arabic/English intents mapped
/// to whitelisted engine commands only. Offline regex fallback built in.
class _Omnibox extends ConsumerStatefulWidget {
  const _Omnibox();

  @override
  ConsumerState<_Omnibox> createState() => _OmniboxState();
}

class _OmniboxState extends ConsumerState<_Omnibox> {
  final _controller = TextEditingController();
  final _focus = FocusNode();
  bool _busy = false;
  String? _reply;

  @override
  void dispose() {
    _controller.dispose();
    _focus.dispose();
    super.dispose();
  }

  Future<void> _run() async {
    final text = _controller.text.trim();
    if (text.isEmpty) return;
    setState(() => _busy = true);
    try {
      final res =
          await ref.read(engineIpcProvider).request('nl.command', {'text': text});
      final nl = (res as Map)['nl'] as Map;
      setState(() {
        _reply = (nl['reply'] as String?) ?? 'done';
        _controller.clear();
      });
    } catch (e) {
      setState(() => _reply = 'error: $e');
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        SizedBox(
          width: 320,
          child: TextField(
            controller: _controller,
            focusNode: _focus,
            style: TextStyle(fontSize: 12, color: AppColors.text),
            textAlign: TextAlign.right,
            decoration: InputDecoration(
              isDense: true,
              hintText: context.tr('omnibox.hint'),
              hintStyle:
                  TextStyle(fontSize: 10, color: AppColors.muted),
              prefixIcon: _busy
                  ? Padding(
                      padding: EdgeInsets.all(8),
                      child: SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2)))
                  : Icon(Icons.auto_awesome,
                      size: 15, color: AppColors.cyan),
              filled: true,
              fillColor: AppColors.background,
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
              border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(999),
                  borderSide: BorderSide(color: AppColors.border)),
              enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(999),
                  borderSide: BorderSide(color: AppColors.border)),
              focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(999),
                  borderSide: BorderSide(color: AppColors.cyan)),
            ),
            onSubmitted: (_) => _run(),
          ),
        ),
        if (_reply != null)
          Align(
            alignment: AlignmentDirectional.centerStart,
            child: Text(_reply!,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(fontSize: 9, color: AppColors.green)),
          ),
      ],
    );
  }
}
