import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/audio/sound_service.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/handoff.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/router/app_router.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/window/app_identity.dart';
import 'package:mics_app/core/window/tray_panel.dart';
import 'package:mics_app/core/window/window_corners.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

void main(List<String> args) {
  WidgetsFlutterBinding.ensureInitialized();
  // Explorer's "Scan with MI CS" verb starts this process with
  // `--scan "<path>"` (D-041); a plain second launch carries nothing and only
  // comes forward.
  final scanPath = AppHandoff.scanPathFrom(args);
  // window_manager must be initialized before runApp for TitleBarStyle.hidden
  // to take effect on the first frame.
  windowManager.ensureInitialized().then((_) {
    runApp(ProviderScope(child: Bootstrap(scanPath: scanPath)));
  });
}

/// Boots the window (hidden title bar, rounded corners, sizing), then swaps
/// in the real app once settings + i18n are warm.
class Bootstrap extends ConsumerStatefulWidget {
  const Bootstrap({super.key, this.scanPath});

  /// The path this launch was started to scan (`--scan`), or null.
  final String? scanPath;

  @override
  ConsumerState<Bootstrap> createState() => _BootstrapState();
}

class _BootstrapState extends ConsumerState<Bootstrap>
    with WindowListener, TrayListener {
  bool _ready = false;
  AppHandoff? _handoffSub;

  @override
  void initState() {
    super.initState();
    windowManager.addListener(this);
    trayManager.addListener(this);
    _init();
  }

  @override
  void dispose() {
    _handoffSub?.dispose();
    super.dispose();
  }

  /// The icon's right-click menu: the native fallback (D-040). It stays two
  /// labels because that is all `AppendMenuW` can draw — the styled surface is
  /// the tray panel a left click opens, and this is what a right click has
  /// always meant on Windows.
  ///
  /// The two labels come from the language packs, not from string literals
  /// (D-053): this is a tray surface the app itself draws, so it is Arabic or
  /// English with every other label. It is re-drawn on a language change; the
  /// tooltip stays [appDisplayName] because that is the product's own name —
  /// the same string the window title and Task Manager use, not copy.
  Future<void> _setupTray() async {
    await trayManager.setIcon('assets/icons/mics.ico');
    await trayManager.setToolTip(appDisplayName);
    await _applyTrayMenu();
  }

  /// Draws the native menu in the language Settings is set to, and with the
  /// pack's labels rather than the raw keys when the tables are not warm yet.
  Future<void> _applyTrayMenu() async {
    final lang = ref.read(settingsProvider).value?.lang ?? AppLang.ar;
    final tables = ref.read(i18nProvider).value ?? const <String, Map<String, String>>{};
    String label(String key) => lookup(tables, lang, key);
    try {
      await trayManager.setContextMenu(Menu(items: [
        MenuItem(key: 'show', label: label('shell.tray.open')),
        MenuItem.separator(),
        MenuItem(key: 'quit', label: label('shell.tray.quit')),
      ]));
    } catch (_) {
      // A platform where `tray_manager` is not answering (a test, a stripped
      // build) must not throw out of the boot sequence.
    }
  }

  /// Closing the window hides MI CS to the tray and leaves the engine running —
  /// the opt-in half of D-039 (Settings → Protection). Off, which is the
  /// default, closing the window is quitting.
  bool get _closeToTray =>
      ref.read(settingsProvider).value?.closeToTray ?? false;

  /// Ends this app on purpose: ask the engine it started to stop, then close
  /// the window. The engine also holds a handle to this process, so an answer
  /// that never arrives still takes it with us. The panel's `Quit` and the
  /// native menu's are this same method (D-040), and it is a *full* exit: it
  /// stops the engine rather than parking the app in the tray (D-053).
  Future<void> _quit() => ref.read(trayPanelProvider.notifier).quit();

  @override
  void onTrayIconMouseDown() {
    // A left click: the app when it is already on screen, else the panel.
    ref.read(trayPanelProvider.notifier).clickedTray();
  }

  @override
  void onTrayIconRightMouseDown() {
    trayManager.popUpContextMenu();
  }

  @override
  void onWindowBlur() {
    // The panel behaves like a flyout: clicking anywhere else puts it away
    // (without quitting — the engine keeps running, which is the whole point of
    // reaching the tray instead of Task Manager).
    if (ref.read(trayPanelProvider).open) {
      ref.read(trayPanelProvider.notifier).close();
    }
  }

  @override
  void onTrayMenuItemClick(MenuItem item) {
    if (item.key == 'show') {
      ref.read(trayPanelProvider.notifier).showApp();
    } else if (item.key == 'quit') {
      _quit();
    }
  }

  @override
  void onWindowClose() async {
    if (_closeToTray) {
      await windowManager.hide();
      return;
    }
    await _quit();
  }

  @override
  void onWindowMaximize() {
    // A rounding region would cut the corners of a maximized window.
    WindowCorners.apply(rounded: false);
  }

  @override
  void onWindowUnmaximize() {
    WindowCorners.apply(rounded: true);
  }

  @override
  void onWindowRestore() {
    WindowCorners.apply(rounded: true);
  }

  Future<void> _init() async {
    await windowManager.waitUntilReadyToShow(
      const WindowOptions(
        title: appDisplayName,
        minimumSize: Size(1100, 700),
        size: Size(1440, 860),
        center: true,
        skipTaskbar: false,
        titleBarStyle: TitleBarStyle.hidden,
      ),
      () async {
        await windowManager.setPreventClose(true);
        await _setupTray();
        await windowManager.show();
        await windowManager.focus();
        WindowCorners.apply(rounded: true);
      },
    );
    // Engines start with the app — no manual engine launch required.
    final ipc = ref.read(engineIpcProvider);
    // Start the sound router once: it maps engine events to cues (D-004).
    ref.read(soundRouterProvider);
    ref.listenManual(settingsProvider, (prev, next) {
      final s = next.value;
      if (s != null) ipc.spawnEnv = s.engineEnv();
      // The native tray menu is drawn by the app once; a language change has to
      // redraw it, or the right-click menu keeps the old language while every
      // Flutter surface follows Settings (D-053).
      if (prev?.value?.lang != s?.lang) {
        _applyTrayMenu();
      }
    });
    // The tables land after the icon does; redraw once they are there so the
    // menu shows words rather than the keys it was built with.
    ref.listenManual(i18nProvider, (prev, next) {
      _applyTrayMenu();
    });
    final s = ref.read(settingsProvider).value;
    if (s != null) ipc.spawnEnv = s.engineEnv();
    final started = await ipc.ensureRunning();
    if (started && (s?.guardAutostart ?? true)) {
      try {
        await ipc.request('guard.start');
      } catch (_) {}
    }
    if (mounted) setState(() => _ready = true);
    await _handoff(ipc);
  }

  /// The single-instance half of D-041: this launch either hands itself over to
  /// the window that is already open (and ends), or it *is* that window — and
  /// then it scans the path Explorer handed over, if there was one.
  ///
  /// The window is already visible by now (the splash in [build] becomes the
  /// app), so a handover that ends this process is a window that appears and
  /// closes; keeping that beat short is what the early `ensureRunning` above
  /// buys: the engine is up, not spawned.
  Future<void> _handoff(EngineIpc ipc) async {
    final handoff = AppHandoff(ipc: ipc, onActivate: _onActivate);
    _handoffSub = handoff;
    // The window that answers "nobody else is here" is the one that keeps
    // listening for later launches.
    handoff.listen();
    final scanPath = widget.scanPath;
    final delivered = await handoff.announce(path: scanPath);
    if (!mounted) return;
    if (delivered) {
      // Another window has it: leave without touching the engine (a second
      // process never owns the engine it did not start).
      await ref.read(trayPanelProvider.notifier).quit();
      return;
    }
    if (scanPath != null) _onActivate(scanPath);
  }

  /// Raises this window for a handover, and shows + starts the scan when the
  /// handover carried a path.
  void _onActivate(String? path) {
    if (!mounted) return;
    unawaited(windowManager.show());
    unawaited(windowManager.focus());
    if (path == null) return;
    // Absolute, so the path means what the caller typed: the engine resolves a
    // relative one against its own directory, which is not the user's.
    final absolute = File(path).absolute.path;
    ref.read(handedScanProvider.notifier).handOver(absolute);
    appRouter.go('/scanner');
  }

  @override
  Widget build(BuildContext context) {
    if (!_ready) {
      return const MaterialApp(
        debugShowCheckedModeBanner: false,
        home: Scaffold(body: Center(child: CircularProgressIndicator())),
      );
    }
    return const MicsApp();
  }
}

class MicsApp extends ConsumerStatefulWidget {
  const MicsApp({super.key});

  @override
  ConsumerState<MicsApp> createState() => _MicsAppState();
}

class _MicsAppState extends ConsumerState<MicsApp>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    // "Follow the system" must react while the app is open, not only at boot.
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangePlatformBrightness() {
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final settings = ref.watch(settingsProvider);
    final i18n = ref.watch(i18nProvider);
    final lang = settings.value?.lang ?? AppLang.ar;

    // Warm settings + i18n tables before first paint of real UI (with a
    // bounded wait — a broken pack must never hang the splash).
    if (!settings.hasValue || !i18n.hasValue) {
      return const MaterialApp(
        debugShowCheckedModeBanner: false,
        home: Scaffold(body: Center(child: CircularProgressIndicator())),
      );
    }

    // Palette must be applied BEFORE MaterialApp builds its themes. In system
    // mode this reads the *current* platform brightness, which is why the
    // observer above forces a rebuild when Windows switches theme.
    AppTheme.applyPalette(settings.value?.themeMode ?? ThemeMode.dark);

    // Keying on mode+lang forces the whole tree (incl. the cached Router
    // pages) to rebuild — statics-based colors switch instantly.
    return MaterialApp.router(
      key: ValueKey('theme-${settings.value?.themeMode}-lang-$lang'),
      title: appDisplayName,
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: settings.value?.themeMode ?? ThemeMode.dark,
      routerConfig: appRouter,
      // The tray panel paints over whatever route is up, rather than replacing
      // it: same window, same router, so closing the panel returns to the page
      // the user was reading (D-040).
      builder: (context, child) =>
          TrayPanelHost(child: child ?? const SizedBox.shrink()),
      locale: lang.locale,
      supportedLocales: [for (final l in AppLang.all) l.locale],
      localizationsDelegates: const [
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
    );
  }
}
