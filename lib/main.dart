import 'dart:ffi' hide Size;
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/router/app_router.dart';
import 'package:mics_app/core/theme/app_theme.dart';
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

  /// Closing the window hides to tray — the engine (and alerts) keep running.
  Future<void> _setupTray() async {
    await trayManager.setIcon('assets/icons/mics.ico');
    await trayManager.setToolTip('MI CS Command Center');
    await trayManager.setContextMenu(Menu(items: [
      MenuItem(key: 'show', label: 'Open MI CS'),
      MenuItem.separator(),
      MenuItem(key: 'quit', label: 'Quit'),
    ]));
  }

  @override
  void onTrayIconMouseDown() {
    windowManager.show();
    windowManager.focus();
  }

  @override
  void onTrayIconRightMouseDown() {
    trayManager.popUpContextMenu();
  }

  @override
  void onTrayMenuItemClick(MenuItem item) {
    if (item.key == 'show') {
      windowManager.show();
      windowManager.focus();
    } else if (item.key == 'quit') {
      windowManager.destroy();
    }
  }

  @override
  void onWindowClose() async {
    // Minimize to tray instead of quitting; engine keeps protecting.
    await windowManager.hide();
  }

  Future<void> _init() async {
    await windowManager.waitUntilReadyToShow(
      const WindowOptions(
        title: 'MI CS Command Center',
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
        applyWindowCornerRadius();
      },
    );
    // Engines start with the app — no manual engine launch required.
    final ipc = ref.read(engineIpcProvider);
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

/// Windows 11 rounded window corners via DWM (DWMWA_WINDOW_CORNER_PREFERENCE).
/// Gracefully no-ops on Windows 10 / when the window is not found.
void applyWindowCornerRadius() {
  if (!Platform.isWindows) return;
  Pointer<Utf16>? titlePtr;
  try {
    final user32 = DynamicLibrary.open('user32.dll');
    final dwmapi = DynamicLibrary.open('dwmapi.dll');
    // FindWindowW(lpClassName, lpWindowName) — the title goes in the WINDOW
    // NAME slot, not the class slot.
    final findWindow = user32.lookupFunction<
        IntPtr Function(Pointer<Utf16>, Pointer<Utf16>),
        int Function(Pointer<Utf16>, Pointer<Utf16>)>('FindWindowW');
    final setAttr = dwmapi.lookupFunction<
        IntPtr Function(IntPtr, IntPtr, Pointer<Void>, IntPtr),
        int Function(int, int, Pointer<Void>, int)>('DwmSetWindowAttribute');

    titlePtr = 'MI CS Command Center'.toNativeUtf16();
    final hwnd = findWindow(Pointer.fromAddress(0), titlePtr);
    if (hwnd == 0) return;
    const dwmwaWindowCornerPreference = 33;
    const dwmcpRound = 2;
    final pref = malloc<Uint32>();
    pref.value = dwmcpRound;
    setAttr(hwnd, dwmwaWindowCornerPreference, pref.cast(), 4);
    malloc.free(pref);
  } catch (_) {
    // Older Windows: square corners, no failure.
  } finally {
    if (titlePtr != null) malloc.free(titlePtr);
  }
}

class MicsApp extends ConsumerWidget {
  const MicsApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
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

    // Palette must be applied BEFORE MaterialApp builds its themes.
    AppTheme.applyPalette(settings.value?.themeMode ?? ThemeMode.dark);

    return MaterialApp.router(
      title: 'MI CS Command Center',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: settings.value?.themeMode ?? ThemeMode.dark,
      routerConfig: appRouter,
      locale: lang == AppLang.ar ? const Locale('ar') : const Locale('en'),
      supportedLocales: const [Locale('ar'), Locale('en')],
      localizationsDelegates: const [
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
    );
  }
}
