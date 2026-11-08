import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/audio/sound_service.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/router/app_router.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/window/app_identity.dart';
import 'package:mics_app/core/window/tray_panel.dart';
import 'package:mics_app/core/window/window_corners.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // window_manager must be initialized before runApp for TitleBarStyle.hidden
  // to take effect on the first frame.
  windowManager.ensureInitialized().then((_) {
    runApp(const ProviderScope(child: Bootstrap()));
  });
}

/// Boots the window (hidden title bar, rounded corners, sizing), then swaps
/// in the real app once settings + i18n are warm.
class Bootstrap extends ConsumerStatefulWidget {
  const Bootstrap({super.key});

  @override
  ConsumerState<Bootstrap> createState() => _BootstrapState();
}

class _BootstrapState extends ConsumerState<Bootstrap>
    with WindowListener, TrayListener {
  bool _ready = false;

  @override
  void initState() {
    super.initState();
    windowManager.addListener(this);
    trayManager.addListener(this);
    _init();
  }

  /// The icon's right-click menu: the native fallback (D-040). It stays two
  /// labels because that is all `AppendMenuW` can draw — the styled surface is
  /// the tray panel a left click opens, and this is what a right click has
  /// always meant on Windows.
  Future<void> _setupTray() async {
    await trayManager.setIcon('assets/icons/mics.ico');
    await trayManager.setToolTip(appDisplayName);
    await trayManager.setContextMenu(Menu(items: [
      MenuItem(key: 'show', label: 'Open $appDisplayName'),
      MenuItem.separator(),
      MenuItem(key: 'quit', label: 'Quit'),
    ]));
  }

  /// Closing the window hides MI CS to the tray and leaves the engine running —
  /// the opt-in half of D-039 (Settings → Protection). Off, which is the
  /// default, closing the window is quitting.
  bool get _closeToTray =>
      ref.read(settingsProvider).value?.closeToTray ?? false;

  /// Ends this app on purpose: ask the engine it started to stop, then close
  /// the window. The engine also holds a handle to this process, so an answer
  /// that never arrives still takes it with us. The panel's `Quit` and the
  /// native menu's are this same method (D-040).
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
