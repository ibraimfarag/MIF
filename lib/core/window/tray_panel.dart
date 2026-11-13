// The tray's own surface (row 15, D-040).
//
// Windows draws the native tray menu with `AppendMenuW`: labels, separators and
// check marks, and nothing else — no icons, no colours, no typography (measured
// 2026-11-08 in `tray_manager`'s own C++). So "styled" and "native menu" cannot
// both be true, and the styled surface has to be Flutter's.
//
// It is the *same window*, resized and moved above the notification area,
// rather than a second one: one process, one Flutter engine, one Riverpod
// container, so the panel reads the very providers the screens do (guard,
// firewall, connections, settings) and is live without any syncing. A second
// window would need another engine and another container to say the same thing.
//
// The native menu stays where it is, on the icon's right-click, as the fallback
// for anything this panel does not do — and because a left click that opens a
// panel, with a right click that opens the old menu, is what Windows users
// already expect from tray icons.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/window/app_identity.dart';
import 'package:mics_app/providers/providers.dart';
import 'package:mics_app/features/guard/screens/guard_screen.dart';
import 'package:mics_app/features/network/screens/network_monitor_screen.dart';
import 'package:screen_retriever/screen_retriever.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

/// Whether the window is showing the tray panel instead of the app.
class TrayPanelState {
  const TrayPanelState({this.open = false});

  final bool open;
}

/// Opens, closes and anchors the panel, and owns what "quit" means.
///
/// Every window call is best-effort: a platform where `window_manager` is not
/// answering (a test, a stripped build) must leave the panel's *content* usable
/// rather than throw out of a tray click.
class TrayPanelController extends Notifier<TrayPanelState> {
  /// The panel's shape, in logical pixels: wide enough for a two-word action and
  /// its switch, short enough to sit above the tray without covering the desktop.
  static const Size panelSize = Size(392, 486);
  static const Size panelMinimumSize = Size(360, 420);

  /// What the app window was before the panel borrowed it (D-040): the panel is
  /// the same window, so the app's size and place have to come back untouched.
  static const Size appMinimumSize = Size(1100, 700);
  Size? _appSize;
  Offset? _appPosition;

  @override
  TrayPanelState build() => const TrayPanelState();

  /// A left click on the icon: the app if it is already on screen, else the
  /// panel. Clicking a second time puts the panel away.
  Future<void> clickedTray() async {
    if (state.open) {
      await close();
      return;
    }
    final visible = await _safe(() => windowManager.isVisible());
    if (visible == true) {
      await _safe(() => windowManager.show());
      await _safe(() => windowManager.focus());
      return;
    }
    await open();
  }

  /// Shows the panel above the notification area.
  Future<void> open() async {
    if (state.open) return;
    _appSize = await _safe(() => windowManager.getSize());
    _appPosition = await _safe(() => windowManager.getPosition());
    // Content first: the panel is painted before the window is resized, so the
    // resize is never what makes the app's own UI appear at panel size.
    state = const TrayPanelState(open: true);
    await _safe(() => windowManager.setMinimumSize(panelMinimumSize));
    await _safe(() => windowManager.setResizable(false));
    await _safe(() => windowManager.setAlwaysOnTop(true));
    await _safe(() => windowManager.setSkipTaskbar(true));
    await _safe(() => windowManager.setSize(panelSize));
    final anchor = await _anchor();
    await _safe(() => windowManager.setPosition(anchor));
    await _safe(() => windowManager.show());
    await _safe(() => windowManager.focus());
  }

  /// Puts the panel away, and the window back to the app's shape and place.
  Future<void> close() async {
    if (!state.open) return;
    state = const TrayPanelState();
    await _restoreAppWindow();
    await _safe(() => windowManager.hide());
  }

  /// The panel's "Open MI CS": the same window, back in the app's shape.
  Future<void> showApp() async {
    state = const TrayPanelState();
    await _restoreAppWindow();
    await _safe(() => windowManager.show());
    await _safe(() => windowManager.focus());
  }

  /// Ends this app on purpose — the engine it started included (D-039). Both
  /// the panel and the native menu's `Quit` come here, so "quit" means one
  /// thing wherever it is clicked.
  ///
  /// One exit, in one order, and nothing can short-circuit it (D-053): the
  /// engine this app started is asked to stop, and the window is destroyed even
  /// if that stop timed out or threw — a quit that stops half way is an app
  /// still running with nothing on screen.
  Future<void> quit() async {
    await _safe(() => ref.read(engineIpcProvider).stopOwnEngine());
    await _safe(() => windowManager.destroy());
  }

  Future<void> _restoreAppWindow() async {
    await _safe(() => windowManager.setSkipTaskbar(false));
    await _safe(() => windowManager.setAlwaysOnTop(false));
    await _safe(() => windowManager.setResizable(true));
    await _safe(() => windowManager.setMinimumSize(appMinimumSize));
    final size = _appSize;
    final position = _appPosition;
    _appSize = null;
    _appPosition = null;
    if (size != null) await _safe(() => windowManager.setSize(size));
    if (position != null) {
      await _safe(() => windowManager.setPosition(position));
    }
  }

  /// Where the panel sits: above the tray icon itself when the platform can say
  /// where that icon is, and above the work area's bottom-right corner when it
  /// cannot — which is where Windows puts its own tray flyouts, so the fallback
  /// is the place a user already looks. Clamped to the work area either way, so
  /// a taskbar on the left or the top cannot push the panel off the screen.
  Future<Offset> _anchor() async {
    double workLeft = 0;
    double workTop = 0;
    double workWidth = 0;
    double workHeight = 0;
    try {
      // `screen_retriever` reports logical pixels, the same units
      // `window_manager` positions in — and the same ones `tray_manager`'s
      // `getBounds` divides its device pixels down to, so the two agree.
      final display = await screenRetriever.getPrimaryDisplay();
      final origin = display.visiblePosition ?? Offset.zero;
      final area = display.visibleSize ?? display.size;
      workLeft = origin.dx;
      workTop = origin.dy;
      workWidth = area.width;
      workHeight = area.height;
    } catch (_) {
      // No display metrics: the tray icon's own rect is still enough to be
      // right on the common single-monitor layout.
    }
    Rect? icon;
    try {
      icon = await trayManager.getBounds();
    } catch (_) {
      icon = null;
    }

    final anchorRight = icon != null
        ? icon.center.dx + panelSize.width / 2
        : workLeft + workWidth;
    final anchorBottom = icon != null ? icon.top : workTop + workHeight;
    var x = anchorRight - panelSize.width;
    var y = anchorBottom - panelSize.height - 8;
    if (workWidth > 0 && workHeight > 0) {
      x = x.clamp(workLeft, workLeft + workWidth - panelSize.width);
      y = y.clamp(workTop, workTop + workHeight - panelSize.height);
    }
    return Offset(x, y);
  }

  /// Runs a window call and swallows its failure. Returns null when it failed,
  /// which is also what "the platform cannot answer this" looks like.
  Future<T?> _safe<T>(Future<T> Function() call) async {
    try {
      return await call();
    } catch (_) {
      return null;
    }
  }
}

final trayPanelProvider = NotifierProvider<TrayPanelController, TrayPanelState>(
  TrayPanelController.new,
);

/// Paints the panel over the routed app while it is open.
///
/// An overlay rather than a replacement: the panel is the same window as the
/// app, so keeping the router mounted underneath means the page the user was on
/// is still there when the panel closes.
class TrayPanelHost extends ConsumerWidget {
  const TrayPanelHost({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final open = ref.watch(trayPanelProvider).open;
    return open ? const TrayPanel() : child;
  }
}

/// The tray panel: live state and the few actions worth reaching from the
/// notification area, styled — which is the whole reason it is Flutter.
class TrayPanel extends ConsumerStatefulWidget {
  const TrayPanel({super.key});

  @override
  ConsumerState<TrayPanel> createState() => _TrayPanelState();
}

class _TrayPanelState extends ConsumerState<TrayPanel> {
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    // Live numbers, read once as the panel appears: the providers keep them
    // fresh from here (the engine pushes guard events; the app syncs settings).
    WidgetsBinding.instance.addPostFrameCallback((_) => _refresh());
  }

  Future<void> _refresh() async {
    if (!mounted) return;
    await Future.wait([
      ref.read(guardProvider.notifier).refresh(),
      ref.read(firewallProvider.notifier).refresh(),
      ref.read(connectionsProvider.notifier).refresh(),
    ]);
  }

  @override
  Widget build(BuildContext context) {
    final settings = ref.watch(settingsProvider).value;
    final guard = ref.watch(guardProvider);
    final firewall = ref.watch(firewallProvider);
    final connections = ref.watch(connectionsProvider);
    final engine = ref.watch(engineStateProvider).value ?? EngineState.stopped;
    final count = connections.value?.length;

    return Focus(
      autofocus: true,
      onKeyEvent: (node, event) {
        if (event is KeyDownEvent &&
            event.logicalKey == LogicalKeyboardKey.escape) {
          ref.read(trayPanelProvider.notifier).close();
          return KeyEventResult.handled;
        }
        return KeyEventResult.ignored;
      },
      child: Material(
        color: Colors.transparent,
        child: Container(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [AppColors.surface, AppColors.background],
            ),
            border: Border.all(
              color: AppColors.border.withValues(alpha: 0.45),
              width: 1,
            ),
            borderRadius: BorderRadius.circular(18),
          ),
          padding: const EdgeInsets.fromLTRB(18, 16, 18, 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _Header(
                engine: engine,
                onClose: () => ref.read(trayPanelProvider.notifier).close(),
              ),
              const SizedBox(height: 14),
              Row(
                children: [
                  Expanded(
                    child: _Stat(
                      label: context.tr('shell.tray.guard'),
                      value: guard.running
                          ? context.tr('shell.tray.on')
                          : context.tr('shell.tray.off'),
                      accent: guard.running ? AppColors.green : AppColors.muted,
                      icon: Icons.monitor_heart_outlined,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: _Stat(
                      label: context.tr('shell.tray.firewall'),
                      value: firewall.defaultDeny
                          ? context.tr('shell.tray.strict')
                          : context.tr('shell.tray.off'),
                      accent: firewall.defaultDeny
                          ? AppColors.cyan
                          : AppColors.muted,
                      icon: Icons.local_fire_department_outlined,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: _Stat(
                      label: context.tr('shell.tray.connections'),
                      value: count == null ? '—' : '$count',
                      accent: AppColors.text,
                      icon: Icons.lan_outlined,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              Divider(
                color: AppColors.border.withValues(alpha: 0.25),
                height: 1,
              ),
              const SizedBox(height: 4),
              _Toggle(
                icon: Icons.shield_outlined,
                title: context.tr('shell.tray.guardToggle'),
                subtitle: context.tr('shell.tray.guardHint'),
                value: guard.running,
                busy: _busy,
                onChanged: (v) => _setGuard(v),
              ),
              _Toggle(
                icon: Icons.do_not_disturb_on_outlined,
                title: context.tr('shell.tray.dnd'),
                subtitle: context.tr('shell.tray.dndHint'),
                value: settings?.dndMode ?? false,
                enabled: settings != null,
                onChanged: (v) => ref.read(settingsProvider.notifier).setDnd(v),
              ),
              _Toggle(
                icon: Icons.minimize_outlined,
                title: context.tr('shell.tray.background'),
                subtitle: context.tr('shell.tray.backgroundHint'),
                value: settings?.closeToTray ?? false,
                enabled: settings != null,
                onChanged: (v) =>
                    ref.read(settingsProvider.notifier).setCloseToTray(v),
              ),
              const Spacer(),
              Row(
                children: [
                  Expanded(
                    child: FilledButton.icon(
                      onPressed: () =>
                          ref.read(trayPanelProvider.notifier).showApp(),
                      icon: const Icon(Icons.open_in_full, size: 16),
                      label: Text(context.tr('shell.tray.open')),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Tooltip(
                    message: context.tr('shell.tray.quitHint'),
                    child: OutlinedButton(
                      onPressed: () =>
                          ref.read(trayPanelProvider.notifier).quit(),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.red,
                        side: BorderSide(
                          color: AppColors.red.withValues(alpha: 0.55),
                        ),
                      ),
                      child: Text(context.tr('shell.tray.quit')),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// Starts or stops the process guard, then re-reads the engine so the switch
  /// shows what actually happened rather than what was asked for.
  Future<void> _setGuard(bool running) async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      await ref
          .read(engineIpcProvider)
          .request(running ? 'guard.start' : 'guard.stop');
    } catch (_) {
      // The refresh below reports the truth either way.
    }
    await ref.read(guardProvider.notifier).refresh();
    if (mounted) setState(() => _busy = false);
  }
}

class _Header extends StatelessWidget {
  const _Header({required this.engine, required this.onClose});

  final EngineState engine;
  final VoidCallback onClose;

  @override
  Widget build(BuildContext context) {
    final (color, label) = switch (engine) {
      EngineState.running => (
        AppColors.green,
        context.tr('shell.tray.engineUp'),
      ),
      EngineState.reconnecting => (
        AppColors.orange,
        context.tr('shell.tray.engineWait'),
      ),
      EngineState.engineMissing => (
        AppColors.red,
        context.tr('shell.tray.engineMissing'),
      ),
      EngineState.stopped => (
        AppColors.muted,
        context.tr('shell.tray.engineDown'),
      ),
    };
    return Row(
      children: [
        Container(
          width: 36,
          height: 36,
          decoration: BoxDecoration(
            color: AppColors.cyan.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(11),
            border: Border.all(color: AppColors.cyan.withValues(alpha: 0.35)),
          ),
          child: Icon(Icons.security, size: 19, color: AppColors.cyan),
        ),
        const SizedBox(width: 11),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                appDisplayName,
                style: TextStyle(
                  color: AppColors.text,
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                ),
              ),
              Text(
                context.tr('app.tagline'),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: AppColors.muted, fontSize: 11),
              ),
            ],
          ),
        ),
        _Pill(color: color, label: label),
        IconButton(
          onPressed: onClose,
          tooltip: context.tr('shell.tray.close'),
          icon: Icon(Icons.close, size: 17),
          color: AppColors.muted,
          splashRadius: 16,
        ),
      ],
    );
  }
}

/// The engine's state as a dot and a word — the one thing a user opens the
/// panel to check, so it is in the header rather than in a row of its own.
class _Pill extends StatelessWidget {
  const _Pill({required this.color, required this.label});

  final Color color;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(
              color: color,
              fontSize: 10.5,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
}

class _Stat extends StatelessWidget {
  const _Stat({
    required this.label,
    required this.value,
    required this.accent,
    required this.icon,
  });

  final String label;
  final String value;
  final Color accent;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 9),
      decoration: BoxDecoration(
        color: AppColors.background.withValues(alpha: 0.55),
        borderRadius: BorderRadius.circular(11),
        border: Border.all(color: AppColors.border.withValues(alpha: 0.25)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 12, color: AppColors.muted),
              const SizedBox(width: 5),
              Expanded(
                child: Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(color: AppColors.muted, fontSize: 10),
                ),
              ),
            ],
          ),
          const SizedBox(height: 5),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: accent,
              fontSize: 14,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

class _Toggle extends StatelessWidget {
  const _Toggle({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.value,
    required this.onChanged,
    this.enabled = true,
    this.busy = false,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final bool value;
  final bool enabled;
  final bool busy;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          Icon(
            icon,
            size: 16,
            color: enabled
                ? AppColors.muted
                : AppColors.muted.withValues(alpha: 0.4),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: enabled ? AppColors.text : AppColors.muted,
                    fontSize: 12.5,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                Text(
                  subtitle,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(color: AppColors.muted, fontSize: 10.5),
                ),
              ],
            ),
          ),
          Switch(
            value: value,
            onChanged: (enabled && !busy) ? onChanged : null,
          ),
        ],
      ),
    );
  }
}
