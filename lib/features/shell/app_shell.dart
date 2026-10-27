import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/providers/providers.dart';

/// 12-module left icon rail + top bar (score, engine state, language toggle).
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
  const _NavDest(this.route, this.icon, this.labelKey);
}

const _navItems = [
  _NavDest('/dashboard', Icons.shield_outlined, 'nav.dashboard'),
  _NavDest('/audit', Icons.fact_check_outlined, 'nav.audit'),
  _NavDest('/scanner', Icons.bug_report_outlined, 'nav.scanner'),
  _NavDest('/network', Icons.lan_outlined, 'nav.network'),
  _NavDest('/ids', Icons.radar_outlined, 'nav.ids'),
  _NavDest('/vulns', Icons.gpp_maybe_outlined, 'nav.vulns'),
  _NavDest('/guard', Icons.monitor_heart_outlined, 'nav.guard'),
  _NavDest('/canaries', Icons.egg_outlined, 'nav.canaries'),
  _NavDest('/hardening', Icons.lock_reset_outlined, 'nav.hardening'),
  _NavDest('/incidents', Icons.timeline_outlined, 'nav.incidents'),
  _NavDest('/reports', Icons.description_outlined, 'nav.reports'),
  _NavDest('/settings', Icons.settings_outlined, 'nav.settings'),
];

class _AppShellState extends ConsumerState<AppShell> {
  @override
  Widget build(BuildContext context) {
    final engineAsync = ref.watch(engineStateProvider);
    final engineState =
        engineAsync.value ?? ref.read(engineIpcProvider).state;
    final rtl = ref.watch(rtlProvider);

    final loc = GoRouterState.of(context).uri.path;
    final selectedIndex =
        _navItems.indexWhere((d) => loc.startsWith(d.route)).clamp(0, 11);

    return Directionality(
      textDirection: rtl ? TextDirection.rtl : TextDirection.ltr,
      child: Scaffold(
        body: Row(
          children: [
            NavigationRail(
              selectedIndex: selectedIndex,
              onDestinationSelected: (i) =>
                  context.go(_navItems[i].route),
              extended: false,
              minExtendedWidth: 160,
              labelType: NavigationRailLabelType.selected,
              leading: Padding(
                padding: const EdgeInsets.symmetric(vertical: 12),
                child: Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    border: Border.all(color: AppColors.cyan, width: 2),
                  ),
                  child: Icon(Icons.shield, color: AppColors.cyan),
                ),
              ),
              destinations: [
                for (final d in _navItems)
                  NavigationRailDestination(
                    icon: Icon(d.icon),
                    selectedIcon: Icon(d.icon, shadows: [
                      Shadow(
                          color: AppColors.cyan.withValues(alpha: 0.8),
                          blurRadius: 12)
                    ]),
                    label: Text(context.tr(d.labelKey),
                        maxLines: 1, overflow: TextOverflow.ellipsis),
                  ),
              ],
            ),
            VerticalDivider(width: 1, color: AppColors.border),
            Expanded(
              child: Column(
                children: [
                  _TopBar(engineState: engineState),
                  Divider(height: 1, color: AppColors.border),
                  Expanded(child: widget.child),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _TopBar extends ConsumerWidget {
  const _TopBar({required this.engineState});
  final EngineState engineState;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final lang = ref.watch(localeProvider);
    final (color, label) = switch (engineState) {
      EngineState.running => (AppColors.green, 'engine.running'),
      EngineState.reconnecting => (AppColors.orange, 'engine.reconnecting'),
      EngineState.engineMissing => (AppColors.red, 'engine.missing'),
      EngineState.stopped => (AppColors.muted, 'engine.stopped'),
    };

    return Container(
      height: 56,
      color: AppColors.background,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        children: [
          Text(context.tr('app.name'),
              style: TextStyle(
                  color: AppColors.text,
                  fontWeight: FontWeight.w800,
                  fontSize: 15)),
          const SizedBox(width: 12),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(999),
              border: Border.all(color: color.withValues(alpha: 0.5)),
            ),
            child: Row(children: [
              Container(width: 8, height: 8,
                  decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
              const SizedBox(width: 6),
              Text('${context.tr('state.engine')}: ${context.tr(label)}',
                  style: TextStyle(color: color, fontSize: 12)),
            ]),
          ),
          const Spacer(),
          IconButton(
            tooltip: 'Theme',
            onPressed: () {
              final cur = ref.watch(settingsProvider).value?.themeMode ??
                  ThemeMode.dark;
              ref.read(settingsProvider.notifier).setThemeMode(
                  cur == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark);
            },
            icon: Icon(
              (ref.watch(settingsProvider).value?.themeMode ??
                          ThemeMode.dark) ==
                      ThemeMode.dark
                  ? Icons.light_mode
                  : Icons.dark_mode,
              size: 18,
            ),
          ),
          const SizedBox(width: 12, child: _Omnibox()),
          TextButton.icon(
            onPressed: () {
  final cur = ref.read(localeProvider);
  ref.read(settingsProvider.notifier).setLang(cur == AppLang.ar ? AppLang.en : AppLang.ar);
},
            icon: const Icon(Icons.language, size: 18),
            label: Text(lang == AppLang.ar ? 'EN' : 'AR'),
          ),
        ],
      ),
    );
  }
}


/// Natural-language command bar (nl.command): Arabic/English intents mapped
/// to whitelisted engine commands only. Offline regex fallback built in.
class _Omnibox extends ConsumerStatefulWidget {
  const _Omnibox();

  @override
  ConsumerState<_Omnibox> createState() => _OmniboxState();
}

class _OmniboxState extends ConsumerState<_Omnibox> {
  final _controller = TextEditingController();
  bool _busy = false;
  String? _reply;

  @override
  void dispose() {
    _controller.dispose();
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
          width: 340,
          child: TextField(
            controller: _controller,
            style: TextStyle(fontSize: 12, color: AppColors.text),
            textAlign: TextAlign.right,
            decoration: InputDecoration(
              isDense: true,
              hintText: 'اكتب أمراً… «افحص النظام» · «شغل الحارس» · «تقرير»',
              hintStyle: TextStyle(fontSize: 10.5, color: AppColors.muted),
              prefixIcon: _busy
                  ? const Padding(
                      padding: EdgeInsets.all(8),
                      child: SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2)))
                  : Icon(Icons.auto_awesome,
                      size: 15, color: AppColors.cyan),
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
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
                style: TextStyle(
                    fontSize: 9.5, color: AppColors.green)),
          ),
      ],
    );
  }
}
