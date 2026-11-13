import 'dart:convert';
import 'dart:io' show stderr;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Language packs: one folder per language, one JSON file per module
/// (`assets/i18n/<code>/<module>.json`).
///
/// A language is one line in [AppLang.all] plus a folder: nothing else in the
/// app knows that "Arabic" or "English" exist. Adding a module = add it to
/// [i18nModules] and drop the file in every language folder; the parity test in
/// `test/i18n_parity_test.dart` enforces both directions, and
/// `test/lang_registry_test.dart` keeps [AppLang.all] and `assets/i18n/` in
/// step.
class AppLang {
  const AppLang._(this.code, this.nativeName, this.englishName, this.direction);

  /// BCP-47 tag, lower case. Also the asset folder and the value the engine
  /// stores, so the three can never disagree.
  final String code;

  /// How the language names itself - what a picker should show, in every UI
  /// language: an Arabic user looking for English is looking for "English".
  final String nativeName;

  /// The English name, for logs and tests.
  final String englishName;

  /// Which way this language's script runs. The UI reads it instead of
  /// comparing against `AppLang.ar`.
  final TextDirection direction;

  static const ar = AppLang._('ar', 'العربية', 'Arabic', TextDirection.rtl);
  static const en = AppLang._('en', 'English', 'English', TextDirection.ltr);

  /// Every bundled language, in the order the picker shows them.
  static const all = <AppLang>[ar, en];

  /// The language for a stored code, or null when no pack matches. A regional
  /// tag (`en-gb`) falls back to its primary subtag, because a pack is per
  /// language and not per region.
  static AppLang? byCode(String? code) {
    if (code == null || code.isEmpty) return null;
    final tag = code.toLowerCase();
    for (final lang in all) {
      if (lang.code == tag) return lang;
    }
    final primary = tag.split('-').first;
    for (final lang in all) {
      if (lang.code == primary) return lang;
    }
    return null;
  }

  /// Whether this build ships a pack for [code]. Empty is *not* a pack.
  static bool hasPack(String code) => byCode(code) != null;

  /// The language to *render* a stored code in, which is not always the code.
  ///
  /// A code with a pack resolves to it. A code with no pack at all - a
  /// hand-edited `settings.json`, or an external RPC caller, since the picker
  /// only offers what ships - resolves to **English**, the language a missing
  /// *key* already falls back to in [lookup]. Ending the chain in Arabic instead
  /// produced a frame in one language with its gaps in another and told nobody
  /// (D-049). An absent or empty code is the engine's own default, Arabic.
  static AppLang resolve(String? code) {
    final withPack = byCode(code);
    if (withPack != null) return withPack;
    return (code == null || code.trim().isEmpty) ? ar : en;
  }

  bool get isRtl => direction == TextDirection.rtl;

  Locale get locale => Locale(code);

  @override
  bool operator ==(Object other) => other is AppLang && other.code == code;

  @override
  int get hashCode => code.hashCode;

  @override
  String toString() => code;
}

/// Code -> native name, for the pack loader and the parity test.
final Map<String, String> bundledLangs = {
  for (final lang in AppLang.all) lang.code: lang.nativeName,
};

/// Every translation module, in load order. Order does not matter for lookup
/// (keys are flat and unique) but keeps the asset list predictable.
///
/// Every entry here is a file every language folder ships, and
/// `test/lang_registry_test.dart` enforces it in both directions: a module the
/// loader asks for and no folder carries is one failed read per language on
/// every start, which stayed invisible while the loader swallowed it silently
/// (D-050 — `about` was that entry, and the About surface's copy lives with
/// `settings`).
const i18nModules = <String>[
  'app',
  'nav',
  'engine',
  'dashboard',
  'common',
  'audit',
  'scanner',
  'network',
  'ids',
  'vulns',
  'intel',
  'guard',
  'canaries',
  'hardening',
  'incidents',
  'reports',
  'settings',
  'helper',
  'sync',
];

/// Reads one pack file. Injectable so a test can refuse a whole language the
/// way a `pubspec.yaml` that forgets its asset folder does (D-050).
typedef PackReader = Future<String> Function(String assetPath);

/// What one language's load left behind: how many module files were read, how
/// many threw, and the asset path of the first one that did.
class PackLoad {
  const PackLoad(this.code, this.modules, this.failed, this.firstFailure);

  final String code;
  final int modules;
  final int failed;
  final String? firstFailure;

  bool get complete => failed == 0;

  /// Every module failed, so nothing at all was read: the folder is not in the
  /// asset list. That is a different fact from an unread module (D-050).
  bool get nothingLoaded => modules > 0 && failed == modules;
}

/// The one line a pack that did not fully load leaves in the log, or `null`
/// when it loaded every module.
///
/// One line per language, and the two cases are worded apart on purpose: a
/// folder the asset list does not carry is a defect in the build, while a single
/// unread module is the gap the loader deliberately tolerates (D-050).
String? i18nPackLoadNote(PackLoad load) {
  if (load.complete) return null;
  if (load.nothingLoaded) {
    return 'i18n: no pack loaded for "${load.code}" - assets/i18n/${load.code}/ '
        'is not in the asset list (see pubspec.yaml "assets:"), so every key '
        'falls back to English, then to its own name';
  }
  return 'i18n: ${load.failed} of ${load.modules} module(s) did not load for '
      '"${load.code}" (first: ${load.firstFailure ?? 'unknown'}) - the keys '
      'they carry fall back to English, then to their own names';
}

final i18nProvider =
    AsyncNotifierProvider<I18nLoader, Map<String, Map<String, String>>>(
        I18nLoader.new);

class I18nLoader extends AsyncNotifier<Map<String, Map<String, String>>> {
  I18nLoader({PackReader? read, void Function(String line)? log})
      : _read = read ?? _fromBundle,
        _log = log ?? _toStderr;

  static Future<String> _fromBundle(String assetPath) =>
      rootBundle.loadString(assetPath);

  static void _toStderr(String line) => stderr.writeln(line);

  final PackReader _read;
  final void Function(String line) _log;

  /// What each language's load left behind, in `bundledLangs` order - the fact
  /// behind the log line, and behind the sentence Settings shows when a bundled
  /// language loaded nothing (D-050).
  final List<PackLoad> loads = [];

  @override
  Future<Map<String, Map<String, String>>> build() async {
    loads.clear();
    final tables = <String, Map<String, String>>{};
    for (final code in bundledLangs.keys) {
      final table = <String, String>{};
      var failed = 0;
      String? firstFailure;
      for (final module in i18nModules) {
        final path = 'assets/i18n/$code/$module.json';
        try {
          final raw = await _read(path);
          final decoded = (jsonDecode(raw) as Map).cast<String, dynamic>();
          decoded.forEach((k, v) => table[k] = v.toString());
        } catch (_) {
          // A module that has not been translated yet must not break the app;
          // missing keys fall back to English or surface the key itself. The
          // same tolerance covers a whole folder the build does not carry, but
          // that one is *reported*: one log line per language, and Settings
          // names the language it left empty (D-050). Throwing instead would
          // replace a degraded UI with none at all - `lib/main.dart` gates the
          // first frame on this provider ever having a value.
          failed++;
          firstFailure ??= path;
        }
      }
      final load = PackLoad(code, i18nModules.length, failed, firstFailure);
      loads.add(load);
      final note = i18nPackLoadNote(load);
      if (note != null) _log(note);
      tables[code] = table;
    }
    return tables;
  }
}

String lookup(
    Map<String, Map<String, String>> tables, AppLang lang, String key) {
  return tables[lang.code]?[key] ?? tables['en']?[key] ?? key;
}

/// Whether the pack for a bundled [code] loaded any key at all.
///
/// The tables alone cannot tell "nothing translated yet" from "this build does
/// not carry the folder" - both are empty - which is why the loader classifies
/// the load ([PackLoad]) and the screen names the language it left empty
/// (D-050). Every bundled language is expected to load, so empty is a fact
/// about the build rather than about the user's settings.
bool packLoaded(Map<String, Map<String, String>> tables, String code) =>
    (tables[code] ?? const <String, String>{}).isNotEmpty;

// ---------- settings: engine is the source of truth (D-008) ----------

/// Mirrors `engine/src/settings.rs`. The engine owns the document
/// (`%PROGRAMDATA%\MICS\settings.json`); this class is the UI's typed view of
/// exactly the same fields, so the two can never drift.
class AppSettings {
  final AppLang lang;

  /// Storage for [storedLangTag] on the one occasion the two differ. See that
  /// getter for why they can.
  final String? _storedTagOverride;

  /// The tag the engine actually has stored, which is not `lang.code` when that
  /// tag has no pack: `lang` is what to render (D-049), this is what the notice
  /// names, and what a write sends back so a hand-edited tag survives a settings
  /// change that had nothing to do with language. `null` in the constructor
  /// means "same as `lang`", which is what a hand-built `AppSettings` means; the
  /// engine's own document always carries a tag, and an absent one is its
  /// default, Arabic.
  String get storedLangTag => _storedTagOverride ?? lang.code;

  final ThemeMode themeMode;
  final bool guardAutostart;
  /// Closing the window hides MI CS to the tray and leaves the engine running;
  /// off (the default) means closing the window quits the app and the engine it
  /// started stops with it (D-039).
  final bool closeToTray;
  final bool autoResumeScans;
  final bool dndMode;
  final int syncIntervalHours;
  final String nvdApiKey;
  /// Custom sha256 hash feed for `ioc_hashes`; empty = not configured.
  final String iocFeedUrl;
  /// Auth-Key for that feed (abuse.ch style header).
  final String iocFeedKey;
  final String updateManifestUrl;
  final String updateChannel;
  final bool soundEnabled;
  final int soundVolume;
  /// Desktop notification cards (Windows toasts) for protection events.
  final bool toastEnabled;
  final bool scanQuarantineDefault;
  /// Hours between automatic scans; 0 disables them (D-027). The engine owns the
  /// timer; this is the switch the user flips.
  final int scanIntervalHours;
  /// Folder that scheduled scan walks; empty = the engine uses the profile.
  final String scanTarget;
  final List<String> canaryPaths;

  const AppSettings({
    this.lang = AppLang.ar,
    String? storedLangTag,
    this.themeMode = ThemeMode.dark,
    this.guardAutostart = true,
    this.closeToTray = false,
    this.autoResumeScans = true,
    this.dndMode = false,
    this.syncIntervalHours = 6,
    this.nvdApiKey = '',
    this.iocFeedUrl = '',
    this.iocFeedKey = '',
    this.updateManifestUrl = '',
    this.updateChannel = 'stable',
    this.soundEnabled = true,
    this.soundVolume = 70,
    this.toastEnabled = true,
    this.scanQuarantineDefault = true,
    this.scanIntervalHours = 0,
    this.scanTarget = '',
    this.canaryPaths = const [],
  }) : _storedTagOverride = storedLangTag;

  static String themeToString(ThemeMode mode) => switch (mode) {
        ThemeMode.light => 'light',
        ThemeMode.system => 'system',
        _ => 'dark',
      };

  static ThemeMode themeFromString(String value) => switch (value) {
        'light' => ThemeMode.light,
        'system' => ThemeMode.system,
        _ => ThemeMode.dark,
      };

  factory AppSettings.fromEngineJson(Map<String, dynamic> j) {
    final storedLang = (j['lang'] as String?)?.trim() ?? '';
    return AppSettings(
        lang: AppLang.resolve(storedLang),
        storedLangTag: storedLang.isEmpty ? null : storedLang,
        themeMode: themeFromString((j['theme'] as String?) ?? 'dark'),
        guardAutostart: j['guard_autostart'] as bool? ?? true,
        closeToTray: j['close_to_tray'] as bool? ?? false,
        autoResumeScans: j['auto_resume_scans'] as bool? ?? true,
        dndMode: j['dnd'] as bool? ?? false,
        syncIntervalHours: (j['sync_interval_hours'] as num?)?.toInt() ?? 6,
        nvdApiKey: j['nvd_api_key'] as String? ?? '',
        iocFeedUrl: j['ioc_feed_url'] as String? ?? '',
        iocFeedKey: j['ioc_feed_key'] as String? ?? '',
        updateManifestUrl: j['update_manifest_url'] as String? ?? '',
        updateChannel: j['update_channel'] as String? ?? 'stable',
        soundEnabled: j['sound_enabled'] as bool? ?? true,
        soundVolume: (j['sound_volume'] as num?)?.toInt() ?? 70,
        toastEnabled: j['toast_enabled'] as bool? ?? true,
        scanQuarantineDefault: j['scan_quarantine_default'] as bool? ?? true,
        scanIntervalHours: (j['scan_interval_hours'] as num?)?.toInt() ?? 0,
        scanTarget: j['scan_target'] as String? ?? '',
        canaryPaths: (j['canary_paths'] as List? ?? const [])
            .map((e) => e.toString())
            .toList(),
      );
  }

  /// A stored tag that no shipped pack can render, so `lang` is a fallback.
  bool get langPackMissing => !AppLang.hasPack(storedLangTag);

  /// Full document in the engine's own key names.
  Map<String, dynamic> toEngineJson() => {
        'lang': storedLangTag,
        'theme': themeToString(themeMode),
        'guard_autostart': guardAutostart,
        'close_to_tray': closeToTray,
        'auto_resume_scans': autoResumeScans,
        'dnd': dndMode,
        'sync_interval_hours': syncIntervalHours,
        'nvd_api_key': nvdApiKey,
        'ioc_feed_url': iocFeedUrl,
        'ioc_feed_key': iocFeedKey,
        'update_manifest_url': updateManifestUrl,
        'update_channel': updateChannel,
        'sound_enabled': soundEnabled,
        'sound_volume': soundVolume,
        'toast_enabled': toastEnabled,
        'scan_quarantine_default': scanQuarantineDefault,
        'scan_interval_hours': scanIntervalHours,
        'scan_target': scanTarget,
        'canary_paths': canaryPaths,
      };

  /// Environment for the case where *this app* has to start the engine.
  Map<String, String> engineEnv() => {
        'MICS_SYNC_HOURS': syncIntervalHours.toString(),
        'MICS_DND': dndMode ? '1' : '0',
        if (updateManifestUrl.isNotEmpty)
          'MICS_UPDATE_MANIFEST_URL': updateManifestUrl,
      };
}

final settingsProvider =
    AsyncNotifierProvider<SettingsNotifier, AppSettings>(SettingsNotifier.new);

class SettingsNotifier extends AsyncNotifier<AppSettings> {
  /// Local cache so the UI can start before the engine answers (and keeps the
  /// last known theme/language even if the engine is down).
  static const _cacheKey = 'settingsJson';
  static const _migratedKey = 'settingsMigratedV2';

  @override
  Future<AppSettings> build() async {
    final ipc = ref.read(engineIpcProvider);
    try {
      final res = await ipc.request('settings.get');
      var settings =
          AppSettings.fromEngineJson((res as Map).cast<String, dynamic>());
      settings = await _migrateLegacyPrefs(ipc, settings);
      await _writeCache(settings);
      return settings;
    } catch (_) {
      return await _readCache();
    }
  }

  /// One-time move of the old `shared_preferences` values into settings.json.
  Future<AppSettings> _migrateLegacyPrefs(
      EngineIpc ipc, AppSettings fromEngine) async {
    final prefs = await SharedPreferences.getInstance();
    if (prefs.getBool(_migratedKey) == true) return fromEngine;
    final hasLegacy = prefs.containsKey('guardAutostart') ||
        prefs.containsKey('dndMode') ||
        prefs.containsKey('syncIntervalHours') ||
        prefs.containsKey('updateManifestUrl') ||
        prefs.containsKey('lang') ||
        prefs.containsKey('themeMode');
    if (!hasLegacy) {
      await prefs.setBool(_migratedKey, true);
      return fromEngine;
    }
    final legacyLang = (prefs.getString('lang') ?? '').trim();
    final legacy = AppSettings(
      lang: AppLang.resolve(legacyLang),
      storedLangTag: legacyLang.isEmpty ? null : legacyLang,
      themeMode: AppSettings.themeFromString(
          prefs.getString('themeMode') ?? 'dark'),
      guardAutostart: prefs.getBool('guardAutostart') ?? true,
      dndMode: prefs.getBool('dndMode') ?? false,
      syncIntervalHours: prefs.getInt('syncIntervalHours') ?? 6,
      updateManifestUrl: prefs.getString('updateManifestUrl') ?? '',
    );
    // Only carry over values the user actually set: sending empty strings
    // would overwrite the engine's real defaults.
    final patch = legacy.toEngineJson()
      ..removeWhere((key, value) =>
          value == '' || (value is List && value.isEmpty));
    try {
      final res = await ipc.request('settings.set', patch);
      await prefs.setBool(_migratedKey, true);
      return AppSettings.fromEngineJson((res as Map).cast<String, dynamic>());
    } catch (_) {
      return fromEngine;
    }
  }

  /// Applies a partial update: engine persists + validates it, then the state
  /// and the local cache follow. Never rebuilds the object from scratch, which
  /// is what used to wipe every other field when changing language or theme.
  Future<void> patch(Map<String, dynamic> values) async {
    final current = state.value ?? const AppSettings();
    try {
      final res = await ref
          .read(engineIpcProvider)
          .request('settings.set', values);
      final next =
          AppSettings.fromEngineJson((res as Map).cast<String, dynamic>());
      state = AsyncValue.data(next);
      await _writeCache(next);
    } catch (e) {
      // Engine unavailable: apply locally so the UI stays responsive, and let
      // the next successful connect reconcile from the engine document.
      final optimistic = _mergeLocal(current, values);
      state = AsyncValue.data(optimistic);
      await _writeCache(optimistic);
      stderr.writeln('settings.set failed ($e) — applied locally');
    }
  }

  AppSettings _mergeLocal(AppSettings cur, Map<String, dynamic> values) {
    final merged = {...cur.toEngineJson(), ...values};
    return AppSettings.fromEngineJson(merged);
  }

  Future<void> setLang(AppLang lang) =>
      patch({'lang': lang.code});

  Future<void> setThemeMode(ThemeMode mode) =>
      patch({'theme': AppSettings.themeToString(mode)});

  Future<void> setDnd(bool enabled) => patch({'dnd': enabled});

  Future<void> setSoundEnabled(bool enabled) =>
      patch({'sound_enabled': enabled});

  Future<void> setSoundVolume(int volume) =>
      patch({'sound_volume': volume.clamp(0, 100)});

  Future<void> setToastEnabled(bool enabled) =>
      patch({'toast_enabled': enabled});

  Future<void> setAutoResumeScans(bool enabled) =>
      patch({'auto_resume_scans': enabled});

  Future<void> setGuardAutostart(bool enabled) =>
      patch({'guard_autostart': enabled});

  Future<void> setCloseToTray(bool enabled) =>
      patch({'close_to_tray': enabled});

  Future<void> setSyncHours(int hours) =>
      patch({'sync_interval_hours': hours.clamp(1, 168)});

  Future<void> setScanQuarantineDefault(bool enabled) =>
      patch({'scan_quarantine_default': enabled});

  /// 0 is the off switch, and the dropdown's fixed list is the only source of
  /// values; the clamp is here so a hand-edited value cannot reach the engine.
  Future<void> setScanHours(int hours) =>
      patch({'scan_interval_hours': hours == 0 ? 0 : hours.clamp(1, 168)});

  Future<void> setScanTarget(String path) =>
      patch({'scan_target': path.trim()});

  Future<void> setCanaryPaths(List<String> paths) =>
      patch({'canary_paths': paths});

  Future<void> setNvdKey(String key) => patch({'nvd_api_key': key});

  Future<void> setIocFeed(String url, String key) =>
      patch({'ioc_feed_url': url, 'ioc_feed_key': key});

  Future<void> setUpdates(String manifestUrl, String channel) => patch({
        'update_manifest_url': manifestUrl,
        'update_channel': channel,
      });

  Future<AppSettings> _readCache() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_cacheKey);
    if (raw != null) {
      try {
        final decoded = jsonDecode(raw) as Map<String, dynamic>;
        return AppSettings.fromEngineJson(decoded);
      } catch (_) {
        // fall through to defaults
      }
    }
    return const AppSettings();
  }

  Future<void> _writeCache(AppSettings settings) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_cacheKey, jsonEncode(settings.toEngineJson()));
  }
}

// ---------- convenience lookups ----------

extension TrX on BuildContext {
  String tr(String key) {
    final container = ProviderScope.containerOf(this);
    final lang =
        container.read(settingsProvider).value?.lang ?? AppLang.ar;
    final tables = container.read(i18nProvider).value ?? const {};
    return lookup(tables, lang, key);
  }

  AppLang get currentLang =>
      ProviderScope.containerOf(this).read(settingsProvider).value?.lang ??
      AppLang.ar;
}

final rtlProvider = Provider<bool>((ref) {
  return (ref.watch(settingsProvider).value?.lang ?? AppLang.ar).isRtl;
});

/// Backwards-compat shim: old code watched this for the active language.
final localeProvider = Provider<AppLang>((ref) {
  return ref.watch(settingsProvider).value?.lang ?? AppLang.ar;
});
